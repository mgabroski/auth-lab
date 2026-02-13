/**
 * src/shared/messaging/inmem-queue.ts
 *
 * WHY:
 * - Tests need to inspect what messages the service enqueued without running
 *   real email infrastructure.
 * - drain() is the test contract: call it after the HTTP request completes
 *   to get all enqueued messages, then assert on their contents.
 * - Production: di.ts swaps this for a real transport adapter (SQS, etc.)
 *   without touching any service code.
 *
 * RULES:
 * - Implements Queue interface only — no extra methods visible to services.
 * - drain() is only used by test helpers; production code never calls it.
 * - Thread-safety: JavaScript is single-threaded, so the array is safe.
 */

import type { Queue, QueueMessage } from './queue';

export class InMemQueue implements Queue {
  private readonly messages: QueueMessage[] = [];

  enqueue(message: QueueMessage): Promise<void> {
    this.messages.push(message);
    return Promise.resolve();
  }

  /**
   * Returns all enqueued messages and clears the queue.
   * Used by test helpers to inspect what was sent.
   *
   * Generic so tests can get a strongly-typed message array:
   * const msgs = queue.drain<ResetPasswordEmailMessage>();
   */
  drain<T extends QueueMessage = QueueMessage>(): T[] {
    return this.messages.splice(0, this.messages.length) as T[];
  }
}
