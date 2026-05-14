/**
 * backend/src/shared/db/migrations/0024_agent_invite_groups.ts
 *
 * WHY:
 * - Agent invites must remember which active Agent groups were selected when
 *   the invite was issued.
 * - This is provisioning-only persistence. It does not create Operational
 *   Access grants, Person Exceptions, Managed People, scopes, or an Effective
 *   Access Resolver.
 *
 * RULES:
 * - Assignments are tenant-scoped and tied to both the invite and group tenant.
 * - A group archive after invite creation does not delete the assignment; the
 *   acceptance/resend paths revalidate and fail closed.
 * - Rollback removes only this bridge table and the invite composite constraint
 *   owned by this migration.
 */

import { Kysely, sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'invite_agent_groups_invites_id_tenant_unique'
      ) THEN
        ALTER TABLE invites
          ADD CONSTRAINT invite_agent_groups_invites_id_tenant_unique UNIQUE (id, tenant_id);
      END IF;
    END $$;
  `.execute(db);

  await sql`
    CREATE TABLE IF NOT EXISTS invite_agent_groups (
      invite_id   UUID        NOT NULL,
      tenant_id   UUID        NOT NULL,
      group_id    UUID        NOT NULL,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT invite_agent_groups_pkey PRIMARY KEY (invite_id, group_id),
      CONSTRAINT invite_agent_groups_invite_tenant_fkey
        FOREIGN KEY (invite_id, tenant_id)
        REFERENCES invites(id, tenant_id)
        ON DELETE CASCADE,
      CONSTRAINT invite_agent_groups_tenant_fkey
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,
      CONSTRAINT invite_agent_groups_group_tenant_fkey
        FOREIGN KEY (group_id, tenant_id)
        REFERENCES tenant_groups(id, tenant_id)
        ON DELETE RESTRICT
    );
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS invite_agent_groups_tenant_invite_idx
      ON invite_agent_groups (tenant_id, invite_id);
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS invite_agent_groups_tenant_group_idx
      ON invite_agent_groups (tenant_id, group_id);
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`
    DROP INDEX IF EXISTS invite_agent_groups_tenant_group_idx;
    DROP INDEX IF EXISTS invite_agent_groups_tenant_invite_idx;
    DROP TABLE IF EXISTS invite_agent_groups;

    ALTER TABLE invites
      DROP CONSTRAINT IF EXISTS invite_agent_groups_invites_id_tenant_unique;
  `.execute(db);
}
