/**
 * backend/src/modules/settings/services/personal-settings-read.service.ts
 *
 * WHY:
 * - Owns the Personal read DTO behind `GET /settings/modules/personal`.
 * - Keeps the current repo honest: this route now exposes family review plus
 *   field-configuration rule foundations, while the later save contract and
 *   section builder remain intentionally deferred.
 */

import { SettingsErrors } from '../settings.errors';
import { SettingsReadRepo } from '../dal/settings-read.repo';
import type { PersonalSettingsDto } from '../settings.types';
import { deriveSettingsNextAction } from './settings-next-action';
import { PersonalSettingsQueryService } from './personal-settings-query.service';

export class PersonalSettingsReadService {
  constructor(
    private readonly readRepo: SettingsReadRepo,
    private readonly personalQuery: PersonalSettingsQueryService,
  ) {}

  async getPersonalSettings(tenantId: string): Promise<PersonalSettingsDto> {
    const [state, cpHandoff] = await Promise.all([
      this.readRepo.getStateBundle(tenantId),
      this.readRepo.getCpHandoffByTenantId(tenantId),
    ]);

    if (!state) {
      throw new Error(`Settings foundation rows not found for tenant ${tenantId}`);
    }

    const personal = this.personalQuery.build({
      sectionStatus: state.sections.personal.status,
      version: state.sections.personal.version,
      cpRevision: state.sections.personal.appliedCpRevision,
      cpHandoff,
    });

    if (!personal.moduleEnabled) {
      throw SettingsErrors.personalModuleUnavailable();
    }

    return {
      sectionKey: 'personal',
      title: 'Personal settings',
      description:
        'Personal is a guided builder inside one page. This route now exposes family review plus field-rule foundations while keeping the final save contract and section builder out of scope for the current repo state.',
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
      moduleEnabled: true,
      familyReview: {
        title: 'Step 1 — Family review',
        description:
          'Review each CP-allowed Personal family. The current repo keeps family review read-only, but it now shows the real exclusion boundaries that later tenant decisions must respect.',
        summary:
          personal.families.length === 0
            ? 'No allowed families are currently available.'
            : `${personal.families.length} allowed families are visible and aligned with the current Control Plane allowance truth.`,
        families: personal.families,
      },
      fieldConfiguration: personal.fieldConfiguration,
      sectionBuilder: personal.sectionBuilder,
    };
  }
}
