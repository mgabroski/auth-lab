import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import type { EmailAdapter, PlainOutboxPayload } from '../../src/shared/outbox/email.adapter';
import {
  NonRetryableEmailError,
  OutboxWorker,
  RetryableEmailError,
} from '../../src/shared/outbox/outbox.worker';
import type { OutboxMessageType } from '../../src/shared/outbox/outbox.repo';
import { buildTestApp } from '../helpers/build-test-app';

type SendMode = 'success' | 'retryable' | 'nonretryable';

type SentMessage = {
  to: string;
  type: OutboxMessageType;
  idempotencyKey: string;
};

class ScriptedEmailAdapter implements EmailAdapter {
  public readonly sent: SentMessage[] = [];

  constructor(private readonly modeByIdempotencyKey: Record<string, SendMode>) {}

  send(opts: {
    to: string;
    type: OutboxMessageType;
    payload: PlainOutboxPayload;
    idempotencyKey: string;
  }): Promise<void> {
    const mode = this.modeByIdempotencyKey[opts.idempotencyKey] ?? 'success';

    if (mode === 'retryable') {
      return Promise.reject(new RetryableEmailError('smtp_temporarily_unavailable'));
    }

    if (mode === 'nonretryable') {
      return Promise.reject(new NonRetryableEmailError('template_missing'));
    }

    this.sent.push({
      to: opts.to,
      type: opts.type,
      idempotencyKey: opts.idempotencyKey,
    });

    return Promise.resolve();
  }
}

function sentEntriesForKey(sent: SentMessage[], idempotencyKey: string): SentMessage[] {
  return sent.filter((entry) => entry.idempotencyKey === idempotencyKey);
}

async function waitForMessageState(opts: {
  db: Awaited<ReturnType<typeof buildTestApp>>['deps']['db'];
  idempotencyKey: string;
  predicate: (row: {
    status: string;
    attempts: number;
    last_error: string | null;
    available_at: Date;
    locked_at: Date | null;
    locked_by: string | null;
  }) => boolean;
  timeoutMs?: number;
}) {
  const timeoutMs = opts.timeoutMs ?? 4_000;
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    const row = await opts.db
      .selectFrom('outbox_messages')
      .select(['status', 'attempts', 'last_error', 'available_at', 'locked_at', 'locked_by'])
      .where('idempotency_key', '=', opts.idempotencyKey)
      .executeTakeFirst();

    if (row && opts.predicate(row)) {
      return row;
    }

    await new Promise((resolve) => setTimeout(resolve, 25));
  }

  throw new Error(`Timed out waiting for outbox row ${opts.idempotencyKey}`);
}

describe('Outbox worker lifecycle', () => {
  it('claims a pending message, sends it, and marks it sent', async () => {
    const { deps, close } = await buildTestApp();
    const idempotencyKey = `sent-${randomUUID()}`;
    const emailAdapter = new ScriptedEmailAdapter({ [idempotencyKey]: 'success' });
    const worker = new OutboxWorker(
      {
        db: deps.db,
        outboxRepo: deps.outboxRepo,
        outboxEncryption: deps.outboxEncryption,
        emailAdapter,
        logger: deps.logger,
        tokenHasher: deps.tokenHasher,
      },
      {
        pollIntervalMs: 20,
        batchSize: 1,
        maxAttemptsDefault: 3,
        claimLeaseSeconds: 1,
      },
    );

    try {
      await deps.outboxRepo.enqueueWithinTx(deps.db, {
        type: 'email.verify',
        payload: deps.outboxEncryption.encryptPayload({
          token: `token-${randomUUID()}`,
          toEmail: `user-${randomUUID().slice(0, 8)}@example.com`,
          tenantKey: 'tenant-contract',
          userId: randomUUID(),
        }),
        idempotencyKey,
      });

      worker.start();

      const row = await waitForMessageState({
        db: deps.db,
        idempotencyKey,
        predicate: (candidate) =>
          candidate.status === 'sent' &&
          candidate.attempts === 0 &&
          candidate.last_error === null &&
          candidate.locked_at === null &&
          candidate.locked_by === null,
      });

      const sentForTarget = sentEntriesForKey(emailAdapter.sent, idempotencyKey);

      expect(row.status).toBe('sent');
      expect(sentForTarget).toHaveLength(1);
      expect(sentForTarget[0]?.idempotencyKey).toBe(idempotencyKey);
    } finally {
      worker.stop();
      await close();
    }
  });

  it('schedules exponential retry state for retryable failures', async () => {
    const { deps, close } = await buildTestApp();
    const idempotencyKey = `retry-${randomUUID()}`;
    const emailAdapter = new ScriptedEmailAdapter({ [idempotencyKey]: 'retryable' });
    const worker = new OutboxWorker(
      {
        db: deps.db,
        outboxRepo: deps.outboxRepo,
        outboxEncryption: deps.outboxEncryption,
        emailAdapter,
        logger: deps.logger,
        tokenHasher: deps.tokenHasher,
      },
      {
        pollIntervalMs: 20,
        batchSize: 1,
        maxAttemptsDefault: 3,
        claimLeaseSeconds: 1,
      },
    );

    try {
      const before = Date.now();

      await deps.outboxRepo.enqueueWithinTx(deps.db, {
        type: 'password.reset',
        payload: deps.outboxEncryption.encryptPayload({
          token: `token-${randomUUID()}`,
          toEmail: `user-${randomUUID().slice(0, 8)}@example.com`,
          tenantKey: 'tenant-contract',
          userId: randomUUID(),
        }),
        idempotencyKey,
      });

      worker.start();

      const row = await waitForMessageState({
        db: deps.db,
        idempotencyKey,
        predicate: (candidate) =>
          candidate.status === 'pending' &&
          candidate.attempts === 1 &&
          candidate.last_error === 'smtp_temporarily_unavailable' &&
          candidate.locked_at === null &&
          candidate.locked_by === null,
      });

      const sentForTarget = sentEntriesForKey(emailAdapter.sent, idempotencyKey);

      expect(row.status).toBe('pending');
      expect(row.attempts).toBe(1);
      expect(row.last_error).toBe('smtp_temporarily_unavailable');
      expect(row.available_at.getTime()).toBeGreaterThanOrEqual(before + 2 * 60 * 1000 - 5_000);
      expect(sentForTarget).toHaveLength(0);
    } finally {
      worker.stop();
      await close();
    }
  });

  it('dead-letters immediately for non-retryable failures', async () => {
    const { deps, close } = await buildTestApp();
    const idempotencyKey = `dead-nonretry-${randomUUID()}`;
    const emailAdapter = new ScriptedEmailAdapter({ [idempotencyKey]: 'nonretryable' });
    const worker = new OutboxWorker(
      {
        db: deps.db,
        outboxRepo: deps.outboxRepo,
        outboxEncryption: deps.outboxEncryption,
        emailAdapter,
        logger: deps.logger,
        tokenHasher: deps.tokenHasher,
      },
      {
        pollIntervalMs: 20,
        batchSize: 1,
        maxAttemptsDefault: 3,
        claimLeaseSeconds: 1,
      },
    );

    try {
      await deps.outboxRepo.enqueueWithinTx(deps.db, {
        type: 'invite.created',
        payload: deps.outboxEncryption.encryptPayload({
          token: `token-${randomUUID()}`,
          toEmail: `user-${randomUUID().slice(0, 8)}@example.com`,
          tenantKey: 'tenant-contract',
          userId: randomUUID(),
          inviteId: randomUUID(),
          role: 'MEMBER',
        }),
        idempotencyKey,
      });

      worker.start();

      const row = await waitForMessageState({
        db: deps.db,
        idempotencyKey,
        predicate: (candidate) =>
          candidate.status === 'dead' &&
          candidate.last_error === 'template_missing' &&
          candidate.locked_at === null &&
          candidate.locked_by === null,
      });

      const sentForTarget = sentEntriesForKey(emailAdapter.sent, idempotencyKey);

      expect(row.status).toBe('dead');
      expect(row.attempts).toBe(0);
      expect(row.last_error).toBe('template_missing');
      expect(sentForTarget).toHaveLength(0);
    } finally {
      worker.stop();
      await close();
    }
  });

  it('dead-letters retryable failures once max attempts are exceeded', async () => {
    const { deps, close } = await buildTestApp();
    const idempotencyKey = `dead-max-${randomUUID()}`;
    const emailAdapter = new ScriptedEmailAdapter({ [idempotencyKey]: 'retryable' });
    const worker = new OutboxWorker(
      {
        db: deps.db,
        outboxRepo: deps.outboxRepo,
        outboxEncryption: deps.outboxEncryption,
        emailAdapter,
        logger: deps.logger,
        tokenHasher: deps.tokenHasher,
      },
      {
        pollIntervalMs: 20,
        batchSize: 1,
        maxAttemptsDefault: 2,
        claimLeaseSeconds: 1,
      },
    );

    try {
      await deps.outboxRepo.enqueueWithinTx(deps.db, {
        type: 'password.reset',
        payload: deps.outboxEncryption.encryptPayload({
          token: `token-${randomUUID()}`,
          toEmail: `user-${randomUUID().slice(0, 8)}@example.com`,
          tenantKey: 'tenant-contract',
          userId: randomUUID(),
        }),
        idempotencyKey,
        maxAttempts: 1,
      });

      worker.start();

      const row = await waitForMessageState({
        db: deps.db,
        idempotencyKey,
        predicate: (candidate) =>
          candidate.status === 'dead' &&
          candidate.last_error === 'max_attempts_exceeded:smtp_temporarily_unavailable' &&
          candidate.locked_at === null &&
          candidate.locked_by === null,
      });

      const sentForTarget = sentEntriesForKey(emailAdapter.sent, idempotencyKey);

      expect(row.status).toBe('dead');
      expect(row.last_error).toBe('max_attempts_exceeded:smtp_temporarily_unavailable');
      expect(sentForTarget).toHaveLength(0);
    } finally {
      worker.stop();
      await close();
    }
  });
});
