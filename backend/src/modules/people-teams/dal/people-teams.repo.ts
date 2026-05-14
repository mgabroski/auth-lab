/**
 * backend/src/modules/people-teams/dal/people-teams.repo.ts
 *
 * WHY:
 * - Repository wrapper for People & Teams reads.
 * - Keeps service code independent from raw query construction.
 *
 * RULES:
 * - No transactions started here.
 * - No AppError.
 * - No write methods in this foundation.
 */

import type { DbExecutor } from '../../../shared/db/db';
import {
  selectActiveGroupsByTenantSql,
  selectActivePeopleByTenantSql,
  type PeopleTeamGroupRow,
  type PeopleTeamPersonRow,
} from './people-teams.query-sql';

export class PeopleTeamsRepo {
  constructor(private readonly db: DbExecutor) {}

  withDb(db: DbExecutor): PeopleTeamsRepo {
    return new PeopleTeamsRepo(db);
  }

  listActiveGroups(tenantId: string): Promise<PeopleTeamGroupRow[]> {
    return selectActiveGroupsByTenantSql(this.db, tenantId);
  }

  listActivePeople(tenantId: string): Promise<PeopleTeamPersonRow[]> {
    return selectActivePeopleByTenantSql(this.db, tenantId);
  }
}
