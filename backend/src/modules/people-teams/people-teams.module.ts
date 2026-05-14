/**
 * backend/src/modules/people-teams/people-teams.module.ts
 *
 * WHY:
 * - Top-level module boundary for the People & Teams backend foundation.
 * - Composes tenant-scoped read services without implementing Operational Access.
 */

import type { FastifyInstance } from 'fastify';
import type { DbExecutor } from '../../shared/db/db';
import { PeopleTeamsRepo } from './dal/people-teams.repo';
import { PeopleTeamsController } from './people-teams.controller';
import { registerPeopleTeamsRoutes } from './people-teams.routes';
import { PeopleTeamsService } from './people-teams.service';

export type PeopleTeamsModule = ReturnType<typeof createPeopleTeamsModule>;

export function createPeopleTeamsModule(deps: { db: DbExecutor }) {
  const repo = new PeopleTeamsRepo(deps.db);
  const service = new PeopleTeamsService(repo);
  const controller = new PeopleTeamsController(service);

  return {
    repo,
    service,
    registerRoutes(app: FastifyInstance) {
      registerPeopleTeamsRoutes(app, controller);
    },
  };
}
