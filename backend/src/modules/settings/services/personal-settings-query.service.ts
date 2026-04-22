/**
 * backend/src/modules/settings/services/personal-settings-query.service.ts
 *
 * WHY:
 * - Composes the base Personal foundation DTO from CP allowance truth and the
 *   persisted Personal section state.
 * - Keeps the phase-true boundary explicit: Phase 6 ships family-review
 *   visibility and page framing only, not the full field-configuration or
 *   section-builder save semantics.
 */

import {
  PERSONAL_FAMILY_DEFAULTS,
  PERSONAL_FAMILY_LABELS,
  PERSONAL_FIELD_CATALOG,
  type PersonalFamilyKey,
} from '../../control-plane/accounts/cp-accounts.catalog';
import type { CpSettingsHandoffSnapshot } from '../../control-plane/accounts/handoff/cp-settings-handoff.types';
import type {
  PersonalFamilyReviewItemDto,
  PersonalStepPanelDto,
  SettingsSetupStatus,
} from '../settings.types';

export type PersonalFoundationReadModel = {
  moduleEnabled: boolean;
  families: PersonalFamilyReviewItemDto[];
  warnings: string[];
  blockers: string[];
  fieldConfiguration: PersonalStepPanelDto;
  sectionBuilder: PersonalStepPanelDto;
};

function familyNotes(params: {
  containsLockedRequiredFields: boolean;
  allowedFieldCount: number;
  defaultSelectedFieldCount: number;
  systemManagedFieldKeys: string[];
}): string[] {
  const notes: string[] = [];

  if (params.containsLockedRequiredFields) {
    notes.push('Contains fields that cannot be excluded in later phases.');
  }

  if (params.systemManagedFieldKeys.length > 0) {
    notes.push('Includes system-managed fields that remain read-only for tenants.');
  }

  if (params.allowedFieldCount === 0) {
    notes.push('No CP-allowed fields currently exist in this family.');
  } else {
    notes.push(
      `${params.defaultSelectedFieldCount} of ${params.allowedFieldCount} CP-allowed fields are default-selected.`,
    );
  }

  return notes;
}

export class PersonalSettingsQueryService {
  build(params: {
    sectionStatus: SettingsSetupStatus;
    cpHandoff?: CpSettingsHandoffSnapshot;
  }): PersonalFoundationReadModel {
    const personalAllowance = params.cpHandoff?.allowances.personal;
    const moduleEnabled = params.cpHandoff?.allowances.modules.modules.personal ?? true;

    if (!moduleEnabled) {
      return {
        moduleEnabled: false,
        families: [],
        warnings: [],
        blockers: ['Personal is not allowed by Control Plane for this workspace.'],
        fieldConfiguration: {
          key: 'fieldConfiguration',
          title: 'Field Configuration',
          description: 'Field rules are introduced in the next phase.',
          status: 'FUTURE_PHASE',
          isLiveInCurrentRepo: false,
          summary: 'Not live in this repo yet.',
        },
        sectionBuilder: {
          key: 'sectionBuilder',
          title: 'Section Builder',
          description: 'Section builder rules are introduced in a later phase.',
          status: 'FUTURE_PHASE',
          isLiveInCurrentRepo: false,
          summary: 'Not live in this repo yet.',
        },
      };
    }

    const allowedFamilies = new Map<PersonalFamilyKey, boolean>(
      (personalAllowance?.families ?? []).map((family) => [family.familyKey, family.isAllowed]),
    );

    const fallbackFields = PERSONAL_FIELD_CATALOG.filter((field) => field.defaultAllowed).map(
      (field) => ({
        familyKey: field.familyKey,
        fieldKey: field.fieldKey,
        isAllowed: true,
        defaultSelected: field.defaultSelected,
        minimumRequired: field.minimumRequired,
        isSystemManaged: field.isSystemManaged,
      }),
    );

    const families = PERSONAL_FAMILY_DEFAULTS.filter((family) => {
      const explicit = allowedFamilies.get(family.familyKey);
      return explicit ?? family.defaultAllowed;
    }).map<PersonalFamilyReviewItemDto>((family) => {
      const allowedFields = (personalAllowance?.fields ?? fallbackFields).filter(
        (field) => field.familyKey === family.familyKey && field.isAllowed,
      );
      const requiredFieldKeys = allowedFields
        .filter((field) => field.minimumRequired === 'required')
        .map((field) => field.fieldKey);
      const systemManagedFieldKeys = allowedFields
        .filter((field) => field.isSystemManaged)
        .map((field) => field.fieldKey);
      const containsLockedRequiredFields =
        requiredFieldKeys.length > 0 || systemManagedFieldKeys.length > 0;

      return {
        familyKey: family.familyKey,
        label: PERSONAL_FAMILY_LABELS[family.familyKey] ?? family.label,
        reviewDecision: 'UNREVIEWED',
        reviewStatus: 'NOT_STARTED',
        allowedFieldCount: allowedFields.length,
        defaultSelectedFieldCount: allowedFields.filter((field) => field.defaultSelected).length,
        containsLockedRequiredFields,
        canExclude: !containsLockedRequiredFields,
        requiredFieldKeys,
        systemManagedFieldKeys,
        notes: familyNotes({
          containsLockedRequiredFields,
          allowedFieldCount: allowedFields.length,
          defaultSelectedFieldCount: allowedFields.filter((field) => field.defaultSelected).length,
          systemManagedFieldKeys,
        }),
      };
    });

    const warnings: string[] = [];
    const blockers: string[] = [];

    if (params.sectionStatus === 'NEEDS_REVIEW') {
      warnings.push('Platform changes require your review before Personal can return to Complete.');
    }

    if (families.length === 0) {
      warnings.push('No Personal families are currently allowed by Control Plane.');
    }

    return {
      moduleEnabled: true,
      families,
      warnings,
      blockers,
      fieldConfiguration: {
        key: 'fieldConfiguration',
        title: 'Field Configuration',
        description:
          'Field-level include/exclude, required/optional, and masked/unmasked rules begin in the next phase.',
        status: 'FUTURE_PHASE',
        isLiveInCurrentRepo: false,
        summary:
          'Phase 6 stops after family-review foundations. Field-level editing is intentionally not live yet.',
      },
      sectionBuilder: {
        key: 'sectionBuilder',
        title: 'Section Builder',
        description:
          'Default section generation and the simple section builder land after field configuration.',
        status: 'FUTURE_PHASE',
        isLiveInCurrentRepo: false,
        summary:
          'Phase 6 does not ship section creation, rearrangement, or final Personal save semantics.',
      },
    };
  }
}
