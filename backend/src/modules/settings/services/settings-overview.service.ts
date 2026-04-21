/**
 * backend/src/modules/settings/services/settings-overview.service.ts
 *
 * WHY:
 * - Composes the first real Settings overview read surface from persisted
 *   Settings-native truth plus the locked v1 route/classification model.
 * - Keeps overview-card treatment, placeholder handling, and next-action
 *   derivation out of controllers.
 */

import { SettingsReadRepo } from '../dal/settings-read.repo';
import {
  SETTINGS_SECTION_ROUTES,
  type SettingsNextAction,
  type SettingsOverviewCardDto,
  type SettingsOverviewDto,
} from '../settings.types';
import { AccessSettingsQueryService } from './access-settings-query.service';
import { AccountSettingsQueryService } from './account-settings-query.service';
import { ModulesHubQueryService } from './modules-hub-query.service';
import { IntegrationsSettingsQueryService } from './integrations-settings-query.service';

function deriveNextAction(params: {
  overallStatus: SettingsOverviewDto['overallStatus'];
  accessStatus: SettingsOverviewCardDto['status'];
  personalStatus: SettingsOverviewCardDto['status'];
  personalRequired: boolean;
}): SettingsNextAction | null {
  if (params.overallStatus === 'COMPLETE') {
    return null;
  }

  if (params.accessStatus !== 'COMPLETE') {
    return {
      key: 'access',
      label:
        params.accessStatus === 'NEEDS_REVIEW'
          ? 'Review Access & Security'
          : 'Review Access & Security',
      href: '/admin/settings/access',
    };
  }

  if (params.personalRequired && params.personalStatus !== 'COMPLETE') {
    return {
      key: 'modules',
      label:
        params.personalStatus === 'NEEDS_REVIEW'
          ? 'Review Personal settings'
          : 'Continue Personal setup',
      href: '/admin/settings/modules/personal',
    };
  }

  return null;
}

export class SettingsOverviewService {
  constructor(
    private readonly readRepo: SettingsReadRepo,
    private readonly accessQuery: AccessSettingsQueryService,
    private readonly accountQuery: AccountSettingsQueryService,
    private readonly modulesQuery: ModulesHubQueryService,
    private readonly integrationsQuery: IntegrationsSettingsQueryService,
  ) {}

  async getOverview(tenantId: string): Promise<SettingsOverviewDto> {
    const [state, tenant, cpHandoff] = await Promise.all([
      this.readRepo.getStateBundle(tenantId),
      this.readRepo.getTenant(tenantId),
      this.readRepo.getCpHandoffByTenantId(tenantId),
    ]);

    if (!state) {
      throw new Error(`Settings foundation rows not found for tenant ${tenantId}`);
    }
    if (!tenant) {
      throw new Error(`Tenant not found for settings overview: ${tenantId}`);
    }

    const accessModel = this.accessQuery.build({ tenant, cpHandoff });
    const accountModel = this.accountQuery.build({ cpHandoff });
    const modulesModel = this.modulesQuery.build({
      personalStatus: state.sections.personal.status,
      cpHandoff,
    });
    const integrationsModel = this.integrationsQuery.build({ tenant, cpHandoff });

    const cards: SettingsOverviewCardDto[] = [
      {
        key: 'access',
        title: SETTINGS_SECTION_ROUTES.access.title,
        description: SETTINGS_SECTION_ROUTES.access.description,
        href: SETTINGS_SECTION_ROUTES.access.href,
        classification: SETTINGS_SECTION_ROUTES.access.classification,
        status: state.sections.access.status,
        warnings: [
          ...(accessModel.loginMethods.google &&
          integrationsModel.google.displayStatus === 'BLOCKED'
            ? integrationsModel.google.warnings
            : []),
          ...(accessModel.loginMethods.microsoft &&
          integrationsModel.microsoft.displayStatus === 'BLOCKED'
            ? integrationsModel.microsoft.warnings
            : []),
        ],
        isRequired: true,
      },
      {
        key: 'account',
        title: SETTINGS_SECTION_ROUTES.account.title,
        description: SETTINGS_SECTION_ROUTES.account.description,
        href: SETTINGS_SECTION_ROUTES.account.href,
        classification: SETTINGS_SECTION_ROUTES.account.classification,
        status: state.sections.account.status,
        warnings: [],
        isRequired: false,
      },
      {
        key: 'modules',
        title: SETTINGS_SECTION_ROUTES.modules.title,
        description: SETTINGS_SECTION_ROUTES.modules.description,
        href: SETTINGS_SECTION_ROUTES.modules.href,
        classification: SETTINGS_SECTION_ROUTES.modules.classification,
        status: modulesModel.status,
        warnings: modulesModel.personalEnabled
          ? []
          : ['Personal is currently disabled by Control Plane allowance truth.'],
        isRequired: false,
      },
      {
        key: 'integrations',
        title: SETTINGS_SECTION_ROUTES.integrations.title,
        description: SETTINGS_SECTION_ROUTES.integrations.description,
        href: SETTINGS_SECTION_ROUTES.integrations.href,
        classification: SETTINGS_SECTION_ROUTES.integrations.classification,
        status: state.sections.integrations.status,
        warnings: [...integrationsModel.google.warnings, ...integrationsModel.microsoft.warnings],
        isRequired: false,
      },
      {
        key: 'communications',
        title: SETTINGS_SECTION_ROUTES.communications.title,
        description: SETTINGS_SECTION_ROUTES.communications.description,
        href: SETTINGS_SECTION_ROUTES.communications.href,
        classification: SETTINGS_SECTION_ROUTES.communications.classification,
        status: 'PLACEHOLDER',
        warnings: [],
        isRequired: false,
      },
      {
        key: 'workspaceExperience',
        title: SETTINGS_SECTION_ROUTES.workspaceExperience.title,
        description: SETTINGS_SECTION_ROUTES.workspaceExperience.description,
        href: SETTINGS_SECTION_ROUTES.workspaceExperience.href,
        classification: SETTINGS_SECTION_ROUTES.workspaceExperience.classification,
        status: 'PLACEHOLDER',
        warnings: [],
        isRequired: false,
      },
    ];

    const nextAction = deriveNextAction({
      overallStatus: state.aggregate.overallStatus,
      accessStatus: state.sections.access.status,
      personalStatus: state.sections.personal.status,
      personalRequired: modulesModel.personalEnabled,
    });

    void accountModel;

    return {
      overallStatus: state.aggregate.overallStatus,
      nextAction,
      cards,
    };
  }
}
