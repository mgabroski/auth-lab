/**
 * backend/src/shared/outbox/noop-email.adapter.ts
 *
 * WHY:
 * - Dev/test adapter: does not actually send email, but preserves control flow.
 * - Provides a clean boundary so production provider can be swapped via DI later.
 *
 * RULES:
 * - Must be idempotent by idempotencyKey (even if it does nothing).
 * - Must not log raw tokens. Must not log raw emails (use emailHash).
 */

import type { Logger } from '../logger/logger';
import type { TokenHasher } from '../security/token-hasher';
import type { EmailAdapter, PlainOutboxPayload } from './email.adapter';
import type { OutboxMessageType } from './outbox.repo';

export class NoopEmailAdapter implements EmailAdapter {
  private readonly seen = new Set<string>();

  constructor(
    private readonly deps: {
      logger: Logger;
      tokenHasher: TokenHasher;
    },
  ) {}

  async send(opts: {
    to: string;
    type: OutboxMessageType;
    payload: PlainOutboxPayload;
    idempotencyKey: string;
  }): Promise<void> {
    if (this.seen.has(opts.idempotencyKey)) {
      // Idempotent no-op
      this.deps.logger.info({
        msg: 'email.noop.duplicate_suppressed',
        event: 'email.noop.duplicate_suppressed',
        type: opts.type,
        idempotencyKey: opts.idempotencyKey,
        emailHash: this.deps.tokenHasher.hash(opts.to.toLowerCase()),
      });
      return;
    }

    this.seen.add(opts.idempotencyKey);

    this.deps.logger.info({
      msg: 'email.noop.sent',
      event: 'email.noop.sent',
      type: opts.type,
      idempotencyKey: opts.idempotencyKey,
      emailHash: this.deps.tokenHasher.hash(opts.to.toLowerCase()),
      // intentionally no token, no raw email
    });

    await Promise.resolve();
  }
}
