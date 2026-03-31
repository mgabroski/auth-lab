/**
 * backend/src/shared/outbox/outbox.worker.ts
 *
 * WHY:
 * - Background worker that delivers outbox email messages safely under concurrency.
 * - Claims rows first, sends outside the DB transaction, then finalizes with
 *   worker-owned guarded updates.
 *
 * RULES:
 * - Must NOT run in nodeEnv=test (DI/build-app enforces).
 * - Must never log raw tokens/emails.
 * - Claim is atomic via locked_at / locked_by lease stamping.
 * - Finalization must be guarded by worker ownership so a reclaimed row cannot
 *   be finalized by a stale worker.
 * - Backoff: now + 2^attempt minutes. Unknown errors treated as retryable.
 * - No `any` and no unsafe casts; validate payload at boundaries.
 *
 * STAGE 3:
 * - Emits email delivery failure metrics for retryable, non-retryable, decrypt,
 *   and max-attempt-exceeded outcomes.
 */

import { randomUUID } from 'node:crypto';
import type { DbExecutor } from '../db/db';
import type { Logger } from '../logger/logger';
import { recordEmailDeliveryFailure } from '../observability/metrics';
import type { TokenHasher } from '../security/token-hasher';

import type { EmailAdapter } from './email.adapter';
import type { EncryptedOutboxPayload, OutboxRepo } from './outbox.repo';
import type { OutboxEncryption } from './outbox-encryption';

export class RetryableEmailError extends Error {}
export class NonRetryableEmailError extends Error {}

export type OutboxWorkerOptions = {
  pollIntervalMs: number;
  batchSize: number;
  maxAttemptsDefault: number;
  claimLeaseSeconds?: number;
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
      claimLeaseSeconds: this.claimLeaseSeconds(),
    });

    this.stopped = false;

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

  private claimLeaseSeconds(): number {
    return this.opts.claimLeaseSeconds ?? 900;
  }

  private async tick(): Promise<void> {
    if (this.stopped) return;

    const start = Date.now();

    try {
      const claimed = await this.deps.outboxRepo.claimBatch(
        this.workerId,
        this.opts.batchSize,
        this.claimLeaseSeconds(),
      );

      for (const msg of claimed) {
        await this.processMessage(msg);
      }

      const dbg = this.deps.logger.debug;
      if (typeof dbg === 'function') {
        dbg({
          msg: 'outbox.tick.done',
          event: 'outbox.tick.done',
          workerId: this.workerId,
          claimedCount: claimed.length,
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

  private async processMessage(msg: {
    id: string;
    attempts: number;
    maxAttempts: number;
    status: 'pending' | 'sent' | 'dead';
    type: 'password.reset' | 'email.verify' | 'invite.created';
    payload: EncryptedOutboxPayload;
    idempotencyKey: string;
  }): Promise<void> {
    const perMsgStart = Date.now();

    this.deps.logger.info({
      msg: 'outbox.claimed',
      event: 'outbox.claimed',
      workerId: this.workerId,
      messageId: msg.id,
      type: msg.type,
    });

    if (msg.status !== 'pending') {
      const updated = await this.deps.outboxRepo.markDeadByWorker(
        msg.id,
        this.workerId,
        `invalid_status:${msg.status}`,
      );

      if (!updated) {
        this.logLostClaim(msg.id, msg.type, 'invalid_status_finalize');
        return;
      }

      this.deps.logger.error({
        msg: 'outbox.dead_lettered',
        event: 'outbox.dead_lettered',
        workerId: this.workerId,
        messageId: msg.id,
        type: msg.type,
        attempts: msg.attempts,
        lastError: `invalid_status:${msg.status}`,
      });
      return;
    }

    const payload: EncryptedOutboxPayload = msg.payload;

    let plain: ReturnType<OutboxEncryption['decryptPayload']>;
    try {
      plain = this.deps.outboxEncryption.decryptPayload(payload);
    } catch (err: unknown) {
      const lastError = err instanceof Error ? err.message : String(err);

      const updated = await this.deps.outboxRepo.markDeadByWorker(
        msg.id,
        this.workerId,
        `decrypt_failed:${lastError}`,
      );

      if (!updated) {
        this.logLostClaim(msg.id, msg.type, 'decrypt_finalize');
        return;
      }

      recordEmailDeliveryFailure({
        messageType: msg.type,
        stage: 'decrypt',
        reason: 'decrypt_failed',
      });

      this.deps.logger.error({
        msg: 'outbox.dead_lettered',
        event: 'outbox.dead_lettered',
        workerId: this.workerId,
        messageId: msg.id,
        type: msg.type,
        attempts: msg.attempts,
        lastError: `decrypt_failed:${lastError}`,
      });
      return;
    }

    const toEmail = plain.toEmail.toLowerCase();
    const emailHash = this.deps.tokenHasher.hash(toEmail);

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

      const updated = await this.deps.outboxRepo.markSentByWorker(msg.id, this.workerId);
      if (!updated) {
        this.logLostClaim(msg.id, msg.type, 'mark_sent');
        return;
      }

      this.deps.logger.info({
        msg: 'outbox.sent',
        event: 'outbox.sent',
        workerId: this.workerId,
        messageId: msg.id,
        type: msg.type,
        latencyMs: Date.now() - perMsgStart,
        emailHash,
      });
    } catch (err: unknown) {
      const classified = this.classifySendError(err);
      const lastError = classified.message;

      if (classified instanceof NonRetryableEmailError) {
        const updated = await this.deps.outboxRepo.markDeadByWorker(
          msg.id,
          this.workerId,
          lastError,
        );

        if (!updated) {
          this.logLostClaim(msg.id, msg.type, 'mark_dead');
          return;
        }

        recordEmailDeliveryFailure({
          messageType: msg.type,
          stage: 'send',
          reason: 'non_retryable',
        });

        this.deps.logger.error({
          msg: 'outbox.dead_lettered',
          event: 'outbox.dead_lettered',
          workerId: this.workerId,
          messageId: msg.id,
          type: msg.type,
          attempts: msg.attempts,
          lastError,
          emailHash,
        });
        return;
      }

      const nextAttempts = msg.attempts + 1;
      const maxAttempts = msg.maxAttempts ?? this.opts.maxAttemptsDefault;

      if (nextAttempts >= maxAttempts) {
        const updated = await this.deps.outboxRepo.markDeadByWorker(
          msg.id,
          this.workerId,
          `max_attempts_exceeded:${lastError}`,
        );

        if (!updated) {
          this.logLostClaim(msg.id, msg.type, 'max_attempts_dead');
          return;
        }

        recordEmailDeliveryFailure({
          messageType: msg.type,
          stage: 'send',
          reason: 'max_attempts_exceeded',
        });

        this.deps.logger.error({
          msg: 'outbox.dead_lettered',
          event: 'outbox.dead_lettered',
          workerId: this.workerId,
          messageId: msg.id,
          type: msg.type,
          attempts: nextAttempts,
          lastError: `max_attempts_exceeded:${lastError}`,
          emailHash,
        });
        return;
      }

      const backoffMinutes = Math.pow(2, nextAttempts);
      const availableAt = new Date(Date.now() + backoffMinutes * 60 * 1000);

      const updated = await this.deps.outboxRepo.scheduleRetryByWorker(
        msg.id,
        this.workerId,
        nextAttempts,
        availableAt,
        lastError,
      );

      if (!updated) {
        this.logLostClaim(msg.id, msg.type, 'schedule_retry');
        return;
      }

      recordEmailDeliveryFailure({
        messageType: msg.type,
        stage: 'send',
        reason: 'retryable',
      });

      this.deps.logger.warn({
        msg: 'outbox.retry_scheduled',
        event: 'outbox.retry_scheduled',
        workerId: this.workerId,
        messageId: msg.id,
        type: msg.type,
        attempt: nextAttempts,
        availableAt: availableAt.toISOString(),
        emailHash,
      });
    }
  }

  private logLostClaim(messageId: string, type: string, stage: string): void {
    this.deps.logger.warn({
      msg: 'outbox.finalize_lost_claim',
      event: 'outbox.finalize_lost_claim',
      workerId: this.workerId,
      messageId,
      type,
      stage,
    });
  }

  private classifySendError(err: unknown): Error {
    if (err instanceof RetryableEmailError || err instanceof NonRetryableEmailError) return err;
    if (err instanceof Error) return new RetryableEmailError(err.message);
    return new RetryableEmailError(String(err));
  }
}
