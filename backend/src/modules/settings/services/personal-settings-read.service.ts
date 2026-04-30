/**
 * backend/src/modules/settings/services/personal-settings-read.service.ts
 *
 * WHY:
 * - Owns the Personal read DTO behind `GET /settings/modules/personal`.
 * - Returns the final v1 Personal builder surface grounded in backend-owned
 *   Personal configuration truth.
 */

import { SettingsErrors } from '../settings.errors';
import { PersonalSettingsRepo } from '../dal/personal-settings.repo';
import { SettingsReadRepo } from '../dal/settings-read.repo';
import type { PersonalSettingsDto } from '../settings.types';
import { deriveSettingsNextAction } from './settings-next-action';
import { PersonalSettingsQueryService } from './personal-settings-query.service';

export class PersonalSettingsReadService {
  constructor(
    private readonly readRepo: SettingsReadRepo,
    private readonly personalRepo: PersonalSettingsRepo,
    private readonly personalQuery: PersonalSettingsQueryService,
  ) {}

  async getPersonalSettings(tenantId: string): Promise<PersonalSettingsDto> {
    const [state, cpHandoff, saved] = await Promise.all([
      this.readRepo.getStateBundle(tenantId),
      this.readRepo.getCpHandoffByTenantId(tenantId),
      this.personalRepo.getByTenantId(tenantId),
    ]);

    if (!state) {
      throw new Error(`Settings foundation rows not found for tenant ${tenantId}`);
    }

    const moduleEnabled = cpHandoff?.allowances.modules.modules.personal ?? true;
    if (!moduleEnabled) {
      throw SettingsErrors.personalModuleUnavailable();
    }

    const personal = this.personalQuery.build({
      sectionStatus: state.sections.personal.status,
      cpHandoff,
      saved,
    });

    return {
      sectionKey: 'personal',
      title: 'Personal settings',
      description:
        'Review allowed Personal families, configure field behavior, and confirm how included fields are grouped into simple sections. Save Personal Configuration is the one authoritative action for this page.',
      status: state.sections.personal.status,
      version: state.sections.personal.version,
      cpRevision: state.sections.personal.appliedCpRevision,
      warnings: personal.warnings,
      blockers: personal.blockers,
      nextAction: deriveSettingsNextAction({
        overallStatus: state.aggregate.overallStatus,
        accessStatus: state.sections.access.status,
        personalStatus: state.sections.personal.status,
        personalRequired: true,
      }),
      progress: personal.progress,
      familyReview: personal.familyReview,
      fieldConfiguration: personal.fieldConfiguration,
      sectionBuilder: personal.sectionBuilder,
      conflictGuidance: personal.conflictGuidance,
      saveActionLabel: 'Save Personal Configuration',
      stickySaveLabel: 'Save Personal Configuration',
    };
  }
}
