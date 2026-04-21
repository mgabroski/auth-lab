/**
 * backend/src/modules/settings/settings.module.ts
 *
 * WHY:
 * - Top-level module boundary for the shipped Settings backend surface.
 * - Composes the real Settings-native state engine, CP cascade service,
 *   bootstrap/overview reads, Access read/write, and the live Account read/write surface.
 */

import type { FastifyInstance } from 'fastify';
import type { AppConfig } from '../../app/config';
import type { DbExecutor } from '../../shared/db/db';
import type { AuditRepo } from '../../shared/audit/audit.repo';
import { SettingsFoundationRepo } from './dal/settings-foundation.repo';
import { SettingsReadRepo } from './dal/settings-read.repo';
import { AccountSettingsRepo } from './dal/account-settings.repo';
import { SsoProviderReadinessGateway } from './gateways/sso-provider-readiness.gateway';
import { SettingsController } from './settings.controller';
import { registerSettingsRoutes } from './settings.routes';
import { AccessSettingsQueryService } from './services/access-settings-query.service';
import { AccessSettingsReadService } from './services/access-settings-read.service';
import { AccessSettingsService } from './services/access-settings.service';
import { AccountSettingsQueryService } from './services/account-settings-query.service';
import { AccountSettingsReadService } from './services/account-settings-read.service';
import { AccountSettingsService } from './services/account-settings.service';
import { IntegrationsSettingsQueryService } from './services/integrations-settings-query.service';
import { ModulesHubQueryService } from './services/modules-hub-query.service';
import { SettingsAuditService } from './services/settings-audit.service';
import { SettingsBootstrapService } from './services/settings-bootstrap.service';
import { SettingsCpCascadeService } from './services/settings-cp-cascade.service';
import { SettingsOverviewService } from './services/settings-overview.service';
import { SettingsStateService } from './services/settings-state.service';

export type SettingsModule = ReturnType<typeof createSettingsModule>;

export function createSettingsModule(deps: {
  db: DbExecutor;
  auditRepo: AuditRepo;
  config: Pick<AppConfig, 'sso'>;
}) {
  const foundationRepo = new SettingsFoundationRepo(deps.db);
  const readRepo = new SettingsReadRepo(deps.db);
  const accountRepo = new AccountSettingsRepo(deps.db);
  const stateService = new SettingsStateService(foundationRepo);
  const cascadeService = new SettingsCpCascadeService(foundationRepo, accountRepo, stateService);
  const readinessGateway = new SsoProviderReadinessGateway({ sso: deps.config.sso });
  const accessQuery = new AccessSettingsQueryService();
  const accountQuery = new AccountSettingsQueryService();
  const modulesQuery = new ModulesHubQueryService();
  const integrationsQuery = new IntegrationsSettingsQueryService(readinessGateway);
  const auditService = new SettingsAuditService(deps.auditRepo);
  const bootstrapService = new SettingsBootstrapService(readRepo);
  const overviewService = new SettingsOverviewService(
    readRepo,
    accessQuery,
    accountQuery,
    modulesQuery,
    integrationsQuery,
  );
  const accessReadService = new AccessSettingsReadService(readRepo, accessQuery, integrationsQuery);
  const accessService = new AccessSettingsService({
    db: deps.db,
    auditRepo: deps.auditRepo,
    readRepo,
    foundationRepo,
    stateService,
    accessQuery,
    integrationsQuery,
    auditService,
  });
  const accountReadService = new AccountSettingsReadService(readRepo, accountRepo, accountQuery);
  const accountService = new AccountSettingsService({
    db: deps.db,
    auditRepo: deps.auditRepo,
    readRepo,
    foundationRepo,
    accountRepo,
    stateService,
    accountQuery,
    auditService,
  });
  const controller = new SettingsController(
    bootstrapService,
    overviewService,
    accessReadService,
    accessService,
    accountReadService,
    accountService,
  );

  return {
    foundationRepo,
    readRepo,
    accountRepo,
    stateService,
    cascadeService,
    bootstrapService,
    overviewService,
    accessReadService,
    accessService,
    accountReadService,
    accountService,
    registerRoutes(app: FastifyInstance) {
      registerSettingsRoutes(app, controller);
    },
  };
}
