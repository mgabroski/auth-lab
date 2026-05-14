/**
 * backend/src/shared/db/migrations/0023_runtime_membership_roles.ts
 *
 * WHY:
 * - Move runtime tenant membership roles to the canonical ADMIN / AGENT / USER
 *   foundation while preserving MEMBER as a legacy compatibility alias during
 *   the migration window.
 *
 * RULES:
 * - Constraints temporarily allow ADMIN / AGENT / USER / MEMBER.
 * - Existing MEMBER rows are backfilled to USER.
 * - Rollback maps USER back to MEMBER, but refuses to continue if AGENT rows
 *   exist because there is no safe legacy equivalent without losing meaning.
 */

import { Kysely, sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`
    ALTER TABLE memberships
      DROP CONSTRAINT IF EXISTS memberships_role_check;
  `.execute(db);

  await sql`
    ALTER TABLE memberships
      ADD CONSTRAINT memberships_role_check
      CHECK (role IN ('ADMIN','AGENT','USER','MEMBER'));
  `.execute(db);

  await sql`
    ALTER TABLE invites
      DROP CONSTRAINT IF EXISTS invites_role_check;
  `.execute(db);

  await sql`
    ALTER TABLE invites
      ADD CONSTRAINT invites_role_check
      CHECK (role IN ('ADMIN','AGENT','USER','MEMBER'));
  `.execute(db);

  await sql`
    UPDATE memberships
    SET role = 'USER', updated_at = now()
    WHERE role = 'MEMBER';
  `.execute(db);

  await sql`
    UPDATE invites
    SET role = 'USER'
    WHERE role = 'MEMBER';
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM memberships WHERE role = 'AGENT') THEN
        RAISE EXCEPTION
          'Cannot rollback 0023_runtime_membership_roles: memberships.role contains AGENT rows with no legacy MEMBER equivalent. Reassign or remove AGENT rows explicitly before rollback.';
      END IF;

      IF EXISTS (SELECT 1 FROM invites WHERE role = 'AGENT') THEN
        RAISE EXCEPTION
          'Cannot rollback 0023_runtime_membership_roles: invites.role contains AGENT rows with no legacy MEMBER equivalent. Reassign or remove AGENT rows explicitly before rollback.';
      END IF;
    END $$;
  `.execute(db);

  await sql`
    UPDATE memberships
    SET role = 'MEMBER', updated_at = now()
    WHERE role = 'USER';
  `.execute(db);

  await sql`
    UPDATE invites
    SET role = 'MEMBER'
    WHERE role = 'USER';
  `.execute(db);

  await sql`
    ALTER TABLE memberships
      DROP CONSTRAINT IF EXISTS memberships_role_check;
  `.execute(db);

  await sql`
    ALTER TABLE memberships
      ADD CONSTRAINT memberships_role_check
      CHECK (role IN ('ADMIN','MEMBER'));
  `.execute(db);

  await sql`
    ALTER TABLE invites
      DROP CONSTRAINT IF EXISTS invites_role_check;
  `.execute(db);

  await sql`
    ALTER TABLE invites
      ADD CONSTRAINT invites_role_check
      CHECK (role IN ('ADMIN','MEMBER'));
  `.execute(db);
}
