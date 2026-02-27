/**
 * backend/src/shared/outbox/outbox.repo.ts
 *
 * WHY:
 * - Single DAL module for DB outbox operations.
 * - Keeps worker + flows simple: they call deep methods, not raw SQL.
 *
 * RULES:
 * - This is DAL only: no business rules, no AppError, no HTTP.
 * - Must work with DbExecutor OR DbTx (same signature via DbExecutor type).
 * - enqueueWithinTx MUST NOT open its own transaction.
 * - claimBatch MUST use the canonical CTE + SELECT FOR UPDATE SKIP LOCKED.
 * - Status MUST remain 'pending' during claim; row lock is the exclusivity mechanism.
 * - No `any` / unsafe access. Validate row shapes at the boundary.
 */

import type { DbExecutor } from '../db/db';
import type { JsonValue } from '../db/database.types';
import { sql } from 'kysely';
import { z } from 'zod';

export type OutboxMessageType = 'password.reset' | 'email.verify' | 'invite.created';

export type EncryptedOutboxPayload = {
  tokenEnc: string; // e.g. "v1:base64..."
  toEmailEnc: string; // e.g. "v1:base64..."
  tenantKey?: string;
  userId?: string;
  inviteId?: string;
  role?: string;
};

export type OutboxMessage = {
  id: string;
  createdAt: Date;
  availableAt: Date;
  lockedAt: Date | null;
  lockedBy: string | null;
  attempts: number;
  maxAttempts: number;
  status: 'pending' | 'sent' | 'dead';
  type: OutboxMessageType;
  payload: EncryptedOutboxPayload;
  idempotencyKey: string;
  lastError: string | null;
};

function toJsonValue(input: unknown): JsonValue {
  return JSON.parse(JSON.stringify(input ?? {})) as JsonValue;
}

const EncryptedOutboxPayloadSchema = z.object({
  tokenEnc: z.string().min(1),
  toEmailEnc: z.string().min(1),
  tenantKey: z.string().optional(),
  userId: z.string().optional(),
  inviteId: z.string().optional(),
  role: z.string().optional(),
});

const OutboxRowSchema = z.object({
  id: z.string().uuid(),
  created_at: z.coerce.date(),
  available_at: z.coerce.date(),
  locked_at: z.coerce.date().nullable(),
  locked_by: z.string().nullable(),
  attempts: z.number().int(),
  max_attempts: z.number().int(),
  status: z.enum(['pending', 'sent', 'dead']),
  type: z.enum(['password.reset', 'email.verify', 'invite.created']),
  payload: EncryptedOutboxPayloadSchema,
  idempotency_key: z.string().min(1),
  last_error: z.string().nullable(),
});

type OutboxRow = z.infer<typeof OutboxRowSchema>;

function mapRow(row: OutboxRow): OutboxMessage {
  return {
    id: row.id,
    createdAt: row.created_at,
    availableAt: row.available_at,
    lockedAt: row.locked_at,
    lockedBy: row.locked_by,
    attempts: row.attempts,
    maxAttempts: row.max_attempts,
    status: row.status,
    type: row.type,
    payload: row.payload,
    idempotencyKey: row.idempotency_key,
    lastError: row.last_error,
  };
}

export class OutboxRepo {
  constructor(private readonly db: DbExecutor) {}

  withDb(db: DbExecutor): OutboxRepo {
    return new OutboxRepo(db);
  }

  async enqueueWithinTx(
    tx: DbExecutor,
    opts: {
      type: OutboxMessageType;
      payload: EncryptedOutboxPayload;
      idempotencyKey: string;
      availableAt?: Date;
      maxAttempts?: number;
    },
  ): Promise<void> {
    await tx
      .insertInto('outbox_messages')
      .values({
        type: opts.type,
        payload: toJsonValue(opts.payload),
        idempotency_key: opts.idempotencyKey,
        available_at: opts.availableAt ?? new Date(),
        max_attempts: opts.maxAttempts ?? 5,
      })
      .execute();
  }

  /**
   * Claims a batch of *pending* rows for this worker.
   *
   * IMPORTANT:
   * - Call this from inside a transaction if you need the row locks to be held
   *   while you send + markSent/scheduleRetry/markDead.
   * - If called outside a transaction, the claim will still work, but locks will
   *   be released immediately after the statement completes.
   */
  async claimBatch(workerId: string, batchSize: number): Promise<OutboxMessage[]> {
    const res = await sql`
      WITH to_claim AS (
        SELECT id
        FROM outbox_messages
        WHERE status = 'pending' AND available_at <= now()
        ORDER BY available_at ASC
        LIMIT ${batchSize}
        FOR UPDATE SKIP LOCKED
      )
      UPDATE outbox_messages o
      SET locked_at = now(),
          locked_by = ${workerId}
      FROM to_claim
      WHERE o.id = to_claim.id
      RETURNING o.*;
    `.execute(this.db);

    const rows = z.array(OutboxRowSchema).parse(res.rows ?? []);
    return rows.map(mapRow);
  }

  async markSent(id: string): Promise<void> {
    await this.db
      .updateTable('outbox_messages')
      .set({
        status: 'sent',
        last_error: null,
      })
      .where('id', '=', id)
      .execute();
  }

  async scheduleRetry(
    id: string,
    attempts: number,
    availableAt: Date,
    lastError: string,
  ): Promise<void> {
    await this.db
      .updateTable('outbox_messages')
      .set({
        attempts,
        available_at: availableAt,
        last_error: lastError,
      })
      .where('id', '=', id)
      .execute();
  }

  async markDead(id: string, lastError: string): Promise<void> {
    await this.db
      .updateTable('outbox_messages')
      .set({
        status: 'dead',
        last_error: lastError,
      })
      .where('id', '=', id)
      .execute();
  }
}
