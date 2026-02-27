/**
 * backend/src/shared/outbox/outbox.worker.ts
 *
 * WHY:
 * - Background worker that delivers outbox email messages safely under concurrency.
 * - Uses SELECT FOR UPDATE SKIP LOCKED to ensure multi-instance correctness.
 *
 * RULES:
 * - Must NOT run in nodeEnv=test (DI/build-app enforces).
 * - Must never log raw tokens/emails.
 * - Claim + send + markSent/scheduleRetry/markDead must happen in ONE transaction scope
 *   so row locks are held during send. If anything fails, tx aborts => row remains pending.
 * - Backoff: now + 2^attempt minutes. Unknown errors treated as retryable.
 * - No `any` and no unsafe casts; validate payload at boundaries.
 */

import { randomUUID } from 'node:crypto';
import type { DbExecutor } from '../db/db';
import type { Logger } from '../logger/logger';
import type { TokenHasher } from '../security/token-hasher';

import type { EmailAdapter } from './email.adapter';
import type { EncryptedOutboxPayload, OutboxRepo } from './outbox.repo';
import type { OutboxEncryption } from './outbox-encryption';

export class RetryableEmailError extends Error {}
export class NonRetryableEmailError extends Error {}

export type OutboxWorkerOptions = {
  pollIntervalMs: number; // default 5000
  batchSize: number; // default 10
  maxAttemptsDefault: number; // default 5
};

export class OutboxWorker {
  private timer: NodeJS.Timeout | null = null;
  private stopped = false;
  private readonly workerId: string;

  constructor(
    private readonly deps: {
      db: DbExecutor;
      outboxRepo: OutboxRepo;
      outboxEncryption: OutboxEncryption;
      emailAdapter: EmailAdapter;
      logger: Logger;
      tokenHasher: TokenHasher;
    },
    private readonly opts: OutboxWorkerOptions,
  ) {
    this.workerId = `outbox-${randomUUID().slice(0, 8)}`;
  }

  start(): void {
    this.deps.logger.info({
      msg: 'outbox.worker.started',
      event: 'outbox.worker.started',
      workerId: this.workerId,
      pollIntervalMs: this.opts.pollIntervalMs,
      batchSize: this.opts.batchSize,
    });

    this.stopped = false;

    // Immediate tick, then interval
    void this.tick();

    this.timer = setInterval(() => {
      void this.tick();
    }, this.opts.pollIntervalMs);
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;

    this.deps.logger.info({
      msg: 'outbox.worker.stopped',
      event: 'outbox.worker.stopped',
      workerId: this.workerId,
    });
  }

  private async tick(): Promise<void> {
    if (this.stopped) return;

    const start = Date.now();

    try {
      await this.deps.db.transaction().execute(async (trx) => {
        const repo = this.deps.outboxRepo.withDb(trx);

        const claimed = await repo.claimBatch(this.workerId, this.opts.batchSize);
        if (claimed.length === 0) return;

        for (const msg of claimed) {
          const perMsgStart = Date.now();

          this.deps.logger.info({
            msg: 'outbox.claimed',
            event: 'outbox.claimed',
            workerId: this.workerId,
            messageId: msg.id,
            type: msg.type,
          });

          // Defensive: only pending rows should ever be claimed
          if (msg.status !== 'pending') {
            await repo.markDead(msg.id, `invalid_status:${msg.status}`);
            this.deps.logger.error({
              msg: 'outbox.dead_lettered',
              event: 'outbox.dead_lettered',
              workerId: this.workerId,
              messageId: msg.id,
              type: msg.type,
              attempts: msg.attempts,
              lastError: `invalid_status:${msg.status}`,
            });
            continue;
          }

          const payload: EncryptedOutboxPayload = msg.payload;

          // Decryption failures are non-retryable (bad config or corrupt payload)
          let plain: ReturnType<OutboxEncryption['decryptPayload']>;
          try {
            plain = this.deps.outboxEncryption.decryptPayload(payload);
          } catch (err: unknown) {
            const lastError = err instanceof Error ? err.message : String(err);
            await repo.markDead(msg.id, `decrypt_failed:${lastError}`);
            this.deps.logger.error({
              msg: 'outbox.dead_lettered',
              event: 'outbox.dead_lettered',
              workerId: this.workerId,
              messageId: msg.id,
              type: msg.type,
              attempts: msg.attempts,
              lastError: `decrypt_failed:${lastError}`,
            });
            continue;
          }

          const toEmail = plain.toEmail.toLowerCase();

          try {
            await this.deps.emailAdapter.send({
              to: toEmail,
              type: msg.type,
              payload: {
                token: plain.token,
                toEmail,
                tenantKey: plain.tenantKey,
                userId: plain.userId,
                inviteId: plain.inviteId,
                role: plain.role,
              },
              idempotencyKey: msg.idempotencyKey,
            });

            await repo.markSent(msg.id);

            this.deps.logger.info({
              msg: 'outbox.sent',
              event: 'outbox.sent',
              workerId: this.workerId,
              messageId: msg.id,
              type: msg.type,
              latencyMs: Date.now() - perMsgStart,
              emailHash: this.deps.tokenHasher.hash(toEmail),
            });
          } catch (err: unknown) {
            const classified = this.classifySendError(err);
            const lastError = classified.message;

            if (classified instanceof NonRetryableEmailError) {
              await repo.markDead(msg.id, lastError);
              this.deps.logger.error({
                msg: 'outbox.dead_lettered',
                event: 'outbox.dead_lettered',
                workerId: this.workerId,
                messageId: msg.id,
                type: msg.type,
                attempts: msg.attempts,
                lastError,
                emailHash: this.deps.tokenHasher.hash(toEmail),
              });
              continue;
            }

            // Retryable (including unknown)
            const nextAttempts = msg.attempts + 1;
            const maxAttempts = msg.maxAttempts ?? this.opts.maxAttemptsDefault;

            if (nextAttempts >= maxAttempts) {
              await repo.markDead(msg.id, `max_attempts_exceeded:${lastError}`);
              this.deps.logger.error({
                msg: 'outbox.dead_lettered',
                event: 'outbox.dead_lettered',
                workerId: this.workerId,
                messageId: msg.id,
                type: msg.type,
                attempts: nextAttempts,
                lastError: `max_attempts_exceeded:${lastError}`,
                emailHash: this.deps.tokenHasher.hash(toEmail),
              });
              continue;
            }

            const backoffMinutes = Math.pow(2, nextAttempts);
            const availableAt = new Date(Date.now() + backoffMinutes * 60 * 1000);

            await repo.scheduleRetry(msg.id, nextAttempts, availableAt, lastError);

            this.deps.logger.warn({
              msg: 'outbox.retry_scheduled',
              event: 'outbox.retry_scheduled',
              workerId: this.workerId,
              messageId: msg.id,
              type: msg.type,
              attempt: nextAttempts,
              availableAt: availableAt.toISOString(),
              emailHash: this.deps.tokenHasher.hash(toEmail),
            });
          }
        }
      });

      // Optional debug logger: keep strictly typed (no casts).
      const dbg = this.deps.logger.debug;
      if (typeof dbg === 'function') {
        dbg({
          msg: 'outbox.tick.done',
          event: 'outbox.tick.done',
          workerId: this.workerId,
          latencyMs: Date.now() - start,
        });
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      this.deps.logger.error({
        msg: 'outbox.tick.failed',
        event: 'outbox.tick.failed',
        workerId: this.workerId,
        error: message,
      });
    }
  }

  private classifySendError(err: unknown): Error {
    if (err instanceof RetryableEmailError || err instanceof NonRetryableEmailError) return err;
    if (err instanceof Error) return new RetryableEmailError(err.message);
    return new RetryableEmailError(String(err));
  }
}
