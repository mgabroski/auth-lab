import { describe, expect, it } from 'vitest';
import { sql } from 'kysely';

import {
  down as downPeopleTeamsMigration,
  up as upPeopleTeamsMigration,
} from '../../src/shared/db/migrations/0022_people_teams_foundation';
import {
  down as downAgentInviteGroupsMigration,
  up as upAgentInviteGroupsMigration,
} from '../../src/shared/db/migrations/0024_agent_invite_groups';
import {
  down as downOperationalAccessGroupGrantsMigration,
  up as upOperationalAccessGroupGrantsMigration,
} from '../../src/shared/db/migrations/0026_operational_access_group_grants';
import {
  down as downOperationalAccessResolverMigration,
  up as upOperationalAccessResolverMigration,
} from '../../src/shared/db/migrations/0027_operational_access_resolver_and_exceptions';
import type { DbExecutor } from '../../src/shared/db/db';
import { buildTestApp } from '../helpers/build-test-app';

type ConstraintExistsRow = {
  exists: boolean;
};

async function constraintExists(
  db: DbExecutor,
  tableName: string,
  constraintName: string,
): Promise<boolean> {
  const result = await sql<ConstraintExistsRow>`
    SELECT EXISTS (
      SELECT 1
      FROM pg_constraint c
      JOIN pg_class t ON t.oid = c.conrelid
      JOIN pg_namespace n ON n.oid = t.relnamespace
      WHERE n.nspname = 'public'
        AND t.relname = ${tableName}
        AND c.conname = ${constraintName}
    ) AS exists;
  `.execute(db);

  return result.rows[0]?.exists === true;
}

async function tableExists(db: DbExecutor, tableName: string): Promise<boolean> {
  const result = await sql<ConstraintExistsRow>`
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.tables
      WHERE table_schema = 'public'
        AND table_name = ${tableName}
    ) AS exists;
  `.execute(db);

  return result.rows[0]?.exists === true;
}

describe('people-teams migration safety', () => {
  it('rolls back only the People & Teams-owned membership constraint', async () => {
    const { deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await upPeopleTeamsMigration(deps.db);

      await expect(
        constraintExists(
          deps.db,
          'memberships',
          'tenant_group_members_memberships_id_tenant_unique',
        ),
      ).resolves.toBe(true);
      await expect(
        constraintExists(deps.db, 'memberships', 'memberships_tenant_user_unique'),
      ).resolves.toBe(true);
      await expect(tableExists(deps.db, 'tenant_groups')).resolves.toBe(true);
      await expect(tableExists(deps.db, 'tenant_group_members')).resolves.toBe(true);

      await downOperationalAccessResolverMigration(deps.db);
      await downOperationalAccessGroupGrantsMigration(deps.db);
      await downAgentInviteGroupsMigration(deps.db);
      await downPeopleTeamsMigration(deps.db);

      await expect(
        constraintExists(
          deps.db,
          'memberships',
          'tenant_group_members_memberships_id_tenant_unique',
        ),
      ).resolves.toBe(false);
      await expect(
        constraintExists(deps.db, 'memberships', 'memberships_tenant_user_unique'),
      ).resolves.toBe(true);
      await expect(tableExists(deps.db, 'tenant_groups')).resolves.toBe(false);
      await expect(tableExists(deps.db, 'tenant_group_members')).resolves.toBe(false);
    } finally {
      await upPeopleTeamsMigration(deps.db);
      await upAgentInviteGroupsMigration(deps.db);
      await upOperationalAccessGroupGrantsMigration(deps.db);
      await upOperationalAccessResolverMigration(deps.db);
      await close();
    }
  });
});
