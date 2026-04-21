/**
 * backend/src/modules/settings/settings.module.ts
 *
 * WHY:
 * - Top-level module boundary for the Phase 2 Settings backend surface.
 * - Composes the first real Settings-native state engine, CP cascade service,
 *   and bootstrap/overview read surfaces without widening into later write
 *   contracts.
 */

import type { FastifyInstance } from 'fastify';
import type { AppConfig } from '../../app/config';
import type { DbExecutor } from '../../shared/db/db';
import { SettingsFoundationRepo } from './dal/settings-foundation.repo';
import { SettingsReadRepo } from './dal/settings-read.repo';
import { SsoProviderReadinessGateway } from './gateways/sso-provider-readiness.gateway';
import { SettingsController } from './settings.controller';
import { registerSettingsRoutes } from './settings.routes';
import { AccessSettingsQueryService } from './services/access-settings-query.service';
import { AccountSettingsQueryService } from './services/account-settings-query.service';
import { IntegrationsSettingsQueryService } from './services/integrations-settings-query.service';
import { ModulesHubQueryService } from './services/modules-hub-query.service';
import { SettingsBootstrapService } from './services/settings-bootstrap.service';
import { SettingsCpCascadeService } from './services/settings-cp-cascade.service';
import { SettingsOverviewService } from './services/settings-overview.service';
import { SettingsStateService } from './services/settings-state.service';

export type SettingsModule = ReturnType<typeof createSettingsModule>;

export function createSettingsModule(deps: { db: DbExecutor; config: Pick<AppConfig, 'sso'> }) {
  const foundationRepo = new SettingsFoundationRepo(deps.db);
  const readRepo = new SettingsReadRepo(deps.db);
  const stateService = new SettingsStateService(foundationRepo);
  const cascadeService = new SettingsCpCascadeService(foundationRepo, stateService);
  const readinessGateway = new SsoProviderReadinessGateway({ sso: deps.config.sso });
  const accessQuery = new AccessSettingsQueryService();
  const accountQuery = new AccountSettingsQueryService();
  const modulesQuery = new ModulesHubQueryService();
  const integrationsQuery = new IntegrationsSettingsQueryService(readinessGateway);
  const bootstrapService = new SettingsBootstrapService(readRepo);
  const overviewService = new SettingsOverviewService(
    readRepo,
    accessQuery,
    accountQuery,
    modulesQuery,
    integrationsQuery,
  );
  const controller = new SettingsController(bootstrapService, overviewService);

  return {
    foundationRepo,
    readRepo,
    stateService,
    cascadeService,
    bootstrapService,
    overviewService,
    registerRoutes(app: FastifyInstance) {
      registerSettingsRoutes(app, controller);
    },
  };
}
