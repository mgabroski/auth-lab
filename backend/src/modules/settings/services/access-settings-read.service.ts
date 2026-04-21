/**
 * backend/src/modules/settings/services/access-settings-read.service.ts
 *
 * WHY:
 * - Owns the real Access & Security read DTO behind `GET /settings/access`.
 * - Composes persisted section state, CP allowance truth, and informational
 *   integration readiness into the locked read-only v1 Access surface.
 */

import { SettingsReadRepo } from '../dal/settings-read.repo';
import type { AccessSettingsDto } from '../settings.types';
import { AccessSettingsQueryService } from './access-settings-query.service';
import { IntegrationsSettingsQueryService } from './integrations-settings-query.service';
import { deriveSettingsNextAction } from './settings-next-action';

export class AccessSettingsReadService {
  constructor(
    private readonly readRepo: SettingsReadRepo,
    private readonly accessQuery: AccessSettingsQueryService,
    private readonly integrationsQuery: IntegrationsSettingsQueryService,
  ) {}

  async getAccessSettings(tenantId: string): Promise<AccessSettingsDto> {
    const [state, tenant, cpHandoff] = await Promise.all([
      this.readRepo.getStateBundle(tenantId),
      this.readRepo.getTenant(tenantId),
      this.readRepo.getCpHandoffByTenantId(tenantId),
    ]);

    if (!state) {
      throw new Error(`Settings foundation rows not found for tenant ${tenantId}`);
    }

    if (!tenant) {
      throw new Error(`Tenant not found for access settings: ${tenantId}`);
    }

    const access = this.accessQuery.build({ tenant, cpHandoff });
    const integrations = this.integrationsQuery.build({ tenant, cpHandoff });

    const googleIntegrationAllowed =
      cpHandoff?.allowances.integrations.integrations.find(
        (integration) => integration.integrationKey === 'integration.sso.google',
      )?.isAllowed ?? tenant.allowedSso.includes('google');

    const microsoftIntegrationAllowed =
      cpHandoff?.allowances.integrations.integrations.find(
        (integration) => integration.integrationKey === 'integration.sso.microsoft',
      )?.isAllowed ?? tenant.allowedSso.includes('microsoft');

    const surface = this.accessQuery.buildSurface({
      access,
      googleIntegrationAllowed,
      microsoftIntegrationAllowed,
      googleIntegrationStatus: integrations.google,
      microsoftIntegrationStatus: integrations.microsoft,
    });

    const personalRequired = cpHandoff?.allowances.modules.modules.personal ?? true;

    return {
      sectionKey: 'access',
      title: 'Access & Security',
      description:
        'Review the platform-managed access envelope for this workspace. Access stays read-only in v1 and completes only when you explicitly acknowledge the current rules.',
      status: state.sections.access.status,
      version: state.sections.access.version,
      cpRevision: state.sections.access.appliedCpRevision,
      canAcknowledge: surface.canAcknowledge,
      acknowledgeLabel: 'Acknowledge & Mark Reviewed',
      groups: surface.groups,
      blockers: surface.blockers,
      warnings: surface.warnings,
      nextAction: deriveSettingsNextAction({
        overallStatus: state.aggregate.overallStatus,
        accessStatus: state.sections.access.status,
        personalStatus: state.sections.personal.status,
        personalRequired,
      }),
    };
  }
}
