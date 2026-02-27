/**
 * backend/src/shared/outbox/email.adapter.ts
 *
 * WHY:
 * - Boundary between durable outbox delivery and actual email provider transport.
 * - Worker is at-least-once; adapter MUST guarantee idempotent delivery per idempotencyKey.
 *
 * RULES:
 * - If send() is called twice with the same idempotencyKey, the user must NOT receive two emails.
 * - Adapters must never log raw tokens; should avoid raw email logs (use emailHash where possible).
 */

import type { OutboxMessageType } from './outbox.repo';

export type PlainOutboxPayload = {
  token: string;
  toEmail: string;
  tenantKey?: string;
  userId?: string;
  inviteId?: string;
  role?: string;
};

export interface EmailAdapter {
  send(opts: {
    to: string;
    type: OutboxMessageType;
    payload: PlainOutboxPayload;
    idempotencyKey: string;
  }): Promise<void>;
}
