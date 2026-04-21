/**
 * backend/src/modules/settings/services/account-settings-read.service.ts
 *
 * WHY:
 * - Owns the real Account Settings read DTO behind `GET /settings/account`.
 * - Composes persisted section state, persisted card state, and CP allowance
 *   truth into the locked v1 Account surface.
 */

import { SettingsReadRepo } from '../dal/settings-read.repo';
import {
  AccountSettingsRepo,
  buildDefaultTenantAccountSettingsRecord,
} from '../dal/account-settings.repo';
import { SettingsErrors } from '../settings.errors';
import type { AccountSettingsDto } from '../settings.types';
import { AccountSettingsQueryService } from './account-settings-query.service';
import { deriveSettingsNextAction } from './settings-next-action';

export class AccountSettingsReadService {
  constructor(
    private readonly readRepo: SettingsReadRepo,
    private readonly accountRepo: AccountSettingsRepo,
    private readonly accountQuery: AccountSettingsQueryService,
  ) {}

  async getAccountSettings(tenantId: string): Promise<AccountSettingsDto> {
    const [state, cpHandoff, stored] = await Promise.all([
      this.readRepo.getStateBundle(tenantId),
      this.readRepo.getCpHandoffByTenantId(tenantId),
      this.accountRepo.getByTenantId(tenantId),
    ]);

    if (!state) {
      throw new Error(`Settings foundation rows not found for tenant ${tenantId}`);
    }

    const allowance = this.accountQuery.build({ cpHandoff });
    if (!this.accountQuery.hasVisibleCards(allowance)) {
      throw SettingsErrors.accountSectionUnavailable();
    }

    const account =
      stored ??
      buildDefaultTenantAccountSettingsRecord({
        tenantId,
        appliedCpRevision: state.sections.account.appliedCpRevision,
      });

    const personalRequired = cpHandoff?.allowances.modules.modules.personal ?? true;
    const cards: AccountSettingsDto['cards'] = [];

    if (this.accountQuery.isBrandingVisible(allowance)) {
      cards.push({
        key: 'branding',
        title: 'Branding',
        description: 'Manage the allowed branding values for this workspace.',
        status: account.branding.status,
        version: account.branding.version,
        cpRevision: account.branding.appliedCpRevision,
        visibility: allowance.branding,
        values: account.branding.values,
      });
    }

    if (this.accountQuery.isOrgStructureVisible(allowance)) {
      cards.push({
        key: 'orgStructure',
        title: 'Organization Structure',
        description: 'Manage the allowed employer and location lists for this workspace.',
        status: account.orgStructure.status,
        version: account.orgStructure.version,
        cpRevision: account.orgStructure.appliedCpRevision,
        visibility: allowance.organizationStructure,
        values: account.orgStructure.values,
      });
    }

    if (allowance.companyCalendar.allowed) {
      cards.push({
        key: 'calendar',
        title: 'Company Calendar',
        description: 'Maintain the observed company dates used by this workspace.',
        status: account.calendar.status,
        version: account.calendar.version,
        cpRevision: account.calendar.appliedCpRevision,
        visibility: { allowed: true },
        values: account.calendar.values,
      });
    }

    return {
      sectionKey: 'account',
      title: 'Account Settings',
      description:
        'Configure the allowed branding, organization structure, and company calendar values for this workspace. Account Settings is live in v1 but remains non-gating.',
      status: state.sections.account.status,
      cards,
      warnings: [],
      nextAction: deriveSettingsNextAction({
        overallStatus: state.aggregate.overallStatus,
        accessStatus: state.sections.access.status,
        personalStatus: state.sections.personal.status,
        personalRequired,
      }),
    };
  }
}
