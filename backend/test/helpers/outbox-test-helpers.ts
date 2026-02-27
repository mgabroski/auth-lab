import { z } from 'zod';
import { sql } from 'kysely';
import type { DbExecutor } from '../../src/shared/db/db';
import type { OutboxEncryption } from '../../src/shared/outbox/outbox-encryption';
import type { OutboxMessageType } from '../../src/shared/outbox/outbox.repo';

const EncryptedPayloadSchema = z.object({
  tokenEnc: z.string().min(1),
  toEmailEnc: z.string().min(1),
  tenantKey: z.string().optional(),
  userId: z.string().optional(),
  inviteId: z.string().optional(),
  role: z.string().optional(),
});

type EncryptedPayload = z.infer<typeof EncryptedPayloadSchema>;

export async function getLatestOutboxPayloadForUser(opts: {
  db: DbExecutor;
  outboxEncryption: OutboxEncryption;
  type: OutboxMessageType;
  userId: string;
}): Promise<{ token: string; toEmail: string; idempotencyKey: string }> {
  const row = await opts.db
    .selectFrom('outbox_messages')
    .select(['payload', 'idempotency_key'])
    .where('type', '=', opts.type)
    .where('status', '=', 'pending')
    .where(sql`payload->>'userId'`, '=', opts.userId)
    .orderBy('created_at', 'desc')
    .limit(1)
    .executeTakeFirst();

  if (!row) {
    throw new Error(`No outbox row found for type=${opts.type} userId=${opts.userId}`);
  }

  const payload: EncryptedPayload = EncryptedPayloadSchema.parse(row.payload);
  const plain = opts.outboxEncryption.decryptPayload(payload);

  return { token: plain.token, toEmail: plain.toEmail, idempotencyKey: row.idempotency_key };
}

export async function getLatestOutboxPayload(opts: {
  db: DbExecutor;
  outboxEncryption: OutboxEncryption;
  type: OutboxMessageType;
  tenantKey?: string;
  userId?: string;
}): Promise<{ token: string; toEmail: string; idempotencyKey: string }> {
  let q = opts.db
    .selectFrom('outbox_messages')
    .select(['payload', 'idempotency_key'])
    .where('type', '=', opts.type)
    .where('status', '=', 'pending');

  if (opts.userId) {
    q = q.where(sql`payload->>'userId'`, '=', opts.userId);
  }

  if (opts.tenantKey) {
    q = q.where(sql`payload->>'tenantKey'`, '=', opts.tenantKey);
  }

  const row = await q.orderBy('created_at', 'desc').limit(1).executeTakeFirst();

  if (!row) {
    throw new Error(`No outbox row found for type=${opts.type}`);
  }

  const payload: EncryptedPayload = EncryptedPayloadSchema.parse(row.payload);
  const plain = opts.outboxEncryption.decryptPayload(payload);

  return { token: plain.token, toEmail: plain.toEmail, idempotencyKey: row.idempotency_key };
}
