/**
 * backend/src/shared/db/migrations/0011_outbox_messages.ts
 *
 * WHY:
 * - Durable auth email delivery requires a DB outbox so we never lose invites/resets/verifications.
 * - Multi-instance safe workers must claim rows using Postgres row locks (SELECT ... FOR UPDATE SKIP LOCKED).
 * - The state machine is intentionally minimal: pending | sent | dead (no processing state).
 *
 * RULES:
 * - Claims use SELECT FOR UPDATE SKIP LOCKED; locked_at/locked_by are diagnostic only (not reclaim logic).
 * - Payload is JSONB and MUST store encrypted fields (tokenEnc/toEmailEnc) once the outbox layer lands.
 * - Idempotency is enforced by a UNIQUE idempotency_key (EmailAdapter/worker uses this for dedupe).
 * - Indexes must support efficient claim scans: (status, available_at) WHERE status='pending'.
 */

import type { Kysely } from 'kysely';
import { sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`
    CREATE TABLE IF NOT EXISTS outbox_messages (
      id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
      available_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

      -- Diagnostic fields (not used for reclaim logic — claims use SELECT FOR UPDATE SKIP LOCKED)
      locked_at       TIMESTAMPTZ,
      locked_by       TEXT,

      -- Lifecycle
      attempts        INTEGER NOT NULL DEFAULT 0,
      max_attempts    INTEGER NOT NULL DEFAULT 5,
      status          TEXT NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending','sent','dead')),

      -- Payload
      type            TEXT NOT NULL,
      payload         JSONB NOT NULL,

      -- Idempotency
      idempotency_key TEXT NOT NULL UNIQUE,
      last_error      TEXT
    );
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS idx_outbox_claimable
    ON outbox_messages (status, available_at)
    WHERE status = 'pending';
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`DROP INDEX IF EXISTS idx_outbox_claimable;`.execute(db);
  await sql`DROP TABLE IF EXISTS outbox_messages;`.execute(db);
}
