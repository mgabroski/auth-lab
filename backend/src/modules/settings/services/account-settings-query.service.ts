/**
 * backend/src/modules/settings/services/account-settings-query.service.ts
 *
 * WHY:
 * - Composes the current Account Settings allowance read model for overview and
 *   section reads.
 * - Owns conservative payload sanitising/validation helpers so write services
 *   stay orchestration-focused.
 * - Uses CP allowance truth when present and a conservative bridge default when
 *   the tenant was not provisioned through the Control Plane.
 */

import type { CpSettingsHandoffSnapshot } from '../../control-plane/accounts/handoff/cp-settings-handoff.types';
import type { SettingsSetupStatus } from '../settings.types';

export type AccountSettingsReadModel = {
  branding: {
    logo: boolean;
    menuColor: boolean;
    fontColor: boolean;
    welcomeMessage: boolean;
  };
  organizationStructure: {
    employers: boolean;
    locations: boolean;
  };
  companyCalendar: {
    allowed: boolean;
  };
};

export type AccountBrandingDraftValues = {
  logoUrl: string | null;
  menuColor: string | null;
  fontColor: string | null;
  welcomeMessage: string | null;
};

export type AccountOrgStructureDraftValues = {
  employers: string[];
  locations: string[];
};

export type AccountCalendarDraftValues = {
  observedDates: string[];
};

function normalizeOptionalString(value: string | null | undefined): string | null {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizeStringList(values: readonly string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();

  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) {
      continue;
    }

    seen.add(trimmed);
    out.push(trimmed);
  }

  return out;
}

export class AccountSettingsQueryService {
  build(params: { cpHandoff?: CpSettingsHandoffSnapshot }): AccountSettingsReadModel {
    if (params.cpHandoff) {
      return params.cpHandoff.allowances.account;
    }

    return {
      branding: {
        logo: true,
        menuColor: true,
        fontColor: true,
        welcomeMessage: true,
      },
      organizationStructure: {
        employers: true,
        locations: true,
      },
      companyCalendar: {
        allowed: true,
      },
    };
  }

  hasVisibleCards(model: AccountSettingsReadModel): boolean {
    return (
      this.isBrandingVisible(model) ||
      this.isOrgStructureVisible(model) ||
      model.companyCalendar.allowed
    );
  }

  isBrandingVisible(model: AccountSettingsReadModel): boolean {
    return (
      model.branding.logo ||
      model.branding.menuColor ||
      model.branding.fontColor ||
      model.branding.welcomeMessage
    );
  }

  isOrgStructureVisible(model: AccountSettingsReadModel): boolean {
    return model.organizationStructure.employers || model.organizationStructure.locations;
  }

  sanitizeBrandingValues(
    values: AccountBrandingDraftValues,
    model: AccountSettingsReadModel,
  ): AccountBrandingDraftValues {
    return {
      logoUrl: model.branding.logo ? normalizeOptionalString(values.logoUrl) : null,
      menuColor: model.branding.menuColor ? normalizeOptionalString(values.menuColor) : null,
      fontColor: model.branding.fontColor ? normalizeOptionalString(values.fontColor) : null,
      welcomeMessage: model.branding.welcomeMessage
        ? normalizeOptionalString(values.welcomeMessage)
        : null,
    };
  }

  sanitizeOrgStructureValues(
    values: AccountOrgStructureDraftValues,
    model: AccountSettingsReadModel,
  ): AccountOrgStructureDraftValues {
    return {
      employers: model.organizationStructure.employers ? normalizeStringList(values.employers) : [],
      locations: model.organizationStructure.locations ? normalizeStringList(values.locations) : [],
    };
  }

  sanitizeCalendarValues(
    values: AccountCalendarDraftValues,
    model: AccountSettingsReadModel,
  ): AccountCalendarDraftValues {
    return {
      observedDates: model.companyCalendar.allowed ? normalizeStringList(values.observedDates) : [],
    };
  }

  isBrandingPayloadValidUnderAllowance(
    values: AccountBrandingDraftValues,
    model: AccountSettingsReadModel,
  ): boolean {
    const normalized = {
      logoUrl: normalizeOptionalString(values.logoUrl),
      menuColor: normalizeOptionalString(values.menuColor),
      fontColor: normalizeOptionalString(values.fontColor),
      welcomeMessage: normalizeOptionalString(values.welcomeMessage),
    };

    return (
      (normalized.logoUrl === null || model.branding.logo) &&
      (normalized.menuColor === null || model.branding.menuColor) &&
      (normalized.fontColor === null || model.branding.fontColor) &&
      (normalized.welcomeMessage === null || model.branding.welcomeMessage)
    );
  }

  isOrgStructurePayloadValidUnderAllowance(
    values: AccountOrgStructureDraftValues,
    model: AccountSettingsReadModel,
  ): boolean {
    const normalized = {
      employers: normalizeStringList(values.employers),
      locations: normalizeStringList(values.locations),
    };

    return (
      (normalized.employers.length === 0 || model.organizationStructure.employers) &&
      (normalized.locations.length === 0 || model.organizationStructure.locations)
    );
  }

  isCalendarPayloadValidUnderAllowance(
    values: AccountCalendarDraftValues,
    model: AccountSettingsReadModel,
  ): boolean {
    const normalized = {
      observedDates: normalizeStringList(values.observedDates),
    };

    return normalized.observedDates.length === 0 || model.companyCalendar.allowed;
  }

  deriveSectionStatus(params: {
    model: AccountSettingsReadModel;
    brandingStatus: SettingsSetupStatus;
    orgStructureStatus: SettingsSetupStatus;
    calendarStatus: SettingsSetupStatus;
  }): SettingsSetupStatus {
    const visibleStatuses: SettingsSetupStatus[] = [];

    if (this.isBrandingVisible(params.model)) {
      visibleStatuses.push(params.brandingStatus);
    }

    if (this.isOrgStructureVisible(params.model)) {
      visibleStatuses.push(params.orgStructureStatus);
    }

    if (params.model.companyCalendar.allowed) {
      visibleStatuses.push(params.calendarStatus);
    }

    if (visibleStatuses.length === 0) {
      return 'NOT_STARTED';
    }

    if (visibleStatuses.some((status) => status === 'NEEDS_REVIEW')) {
      return 'NEEDS_REVIEW';
    }

    if (visibleStatuses.every((status) => status === 'COMPLETE')) {
      return 'COMPLETE';
    }

    if (visibleStatuses.every((status) => status === 'NOT_STARTED')) {
      return 'NOT_STARTED';
    }

    return 'IN_PROGRESS';
  }
}
