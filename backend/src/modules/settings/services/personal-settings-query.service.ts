/**
 * backend/src/modules/settings/services/personal-settings-query.service.ts
 *
 * WHY:
 * - Composes the Personal read model from CP allowance truth and the persisted
 *   Personal section state.
 * - Makes the locked field-configuration rules visible without pretending the
 *   final Personal save contract already exists.
 * - Keeps hidden-vs-excluded, required-floor, and system-managed behavior
 *   explicit and testable before the later save and section-builder phases.
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
  PersonalFieldConfigurationDto,
  PersonalFieldConfigurationFamilyDto,
  PersonalFieldConfigurationItemDto,
  PersonalStepPanelDto,
  SettingsSetupStatus,
} from '../settings.types';

export type PersonalFoundationReadModel = {
  moduleEnabled: boolean;
  families: PersonalFamilyReviewItemDto[];
  warnings: string[];
  blockers: string[];
  fieldConfiguration: PersonalFieldConfigurationDto;
  sectionBuilder: PersonalStepPanelDto;
};

type AllowedPersonalField = {
  familyKey: PersonalFamilyKey;
  fieldKey: string;
  label: string;
  notes: string;
  isAllowed: boolean;
  defaultSelected: boolean;
  minimumRequired: 'none' | 'required' | 'auto';
  isSystemManaged: boolean;
};

function familyNotes(params: {
  containsLockedRequiredFields: boolean;
  allowedFieldCount: number;
  defaultSelectedFieldCount: number;
  systemManagedFieldKeys: string[];
}): string[] {
  const notes: string[] = [];

  if (params.containsLockedRequiredFields) {
    notes.push('Contains fields that cannot be excluded under the locked Personal rules.');
  }

  if (params.systemManagedFieldKeys.length > 0) {
    notes.push('Includes system-managed fields that remain read-only for tenants.');
  }

  if (params.allowedFieldCount === 0) {
    notes.push('No CP-allowed fields currently exist in this family.');
  } else {
    notes.push(
      `${params.defaultSelectedFieldCount} of ${params.allowedFieldCount} CP-allowed fields are currently default-selected by Control Plane.`,
    );
  }

  return notes;
}

function buildAllowedFields(params: {
  cpHandoff?: CpSettingsHandoffSnapshot;
}): AllowedPersonalField[] {
  const fallbackFields: AllowedPersonalField[] = PERSONAL_FIELD_CATALOG.filter(
    (field) => field.defaultAllowed,
  ).map((field) => ({
    familyKey: field.familyKey,
    fieldKey: field.fieldKey,
    label: field.label,
    notes: field.notes,
    isAllowed: true,
    defaultSelected: field.defaultSelected,
    minimumRequired: field.minimumRequired,
    isSystemManaged: field.isSystemManaged,
  }));

  const cpFields = params.cpHandoff?.allowances.personal.fields;

  if (!cpFields || cpFields.length === 0) {
    return fallbackFields;
  }

  const catalogByFieldKey = new Map(PERSONAL_FIELD_CATALOG.map((field) => [field.fieldKey, field]));

  return cpFields
    .map<AllowedPersonalField | null>((field) => {
      const catalog = catalogByFieldKey.get(field.fieldKey);
      if (!catalog) {
        return null;
      }

      return {
        familyKey: field.familyKey,
        fieldKey: field.fieldKey,
        label: catalog.label,
        notes: catalog.notes,
        isAllowed: field.isAllowed,
        defaultSelected: field.defaultSelected,
        minimumRequired: field.minimumRequired,
        isSystemManaged: field.isSystemManaged,
      };
    })
    .filter((field): field is AllowedPersonalField => field !== null);
}

function buildFieldWarnings(field: AllowedPersonalField): string[] {
  const warnings: string[] = [];

  if (!field.isSystemManaged && !field.defaultSelected) {
    warnings.push(
      'This field is CP-allowed but not currently default-selected. It can be included later once the Personal save contract is live.',
    );
  }

  if (!field.isSystemManaged && field.defaultSelected) {
    warnings.push(
      'This field is currently default-selected by Control Plane. Tenant-side include or exclude decisions still require the later Personal save contract.',
    );
  }

  return warnings;
}

function buildFieldBlockers(field: AllowedPersonalField): string[] {
  const blockers: string[] = [];

  if (field.minimumRequired === 'required') {
    blockers.push('Required-floor field. It cannot be made optional or excluded.');
  }

  if (field.isSystemManaged || field.minimumRequired === 'auto') {
    blockers.push('System-managed field. It remains immutable and always read-only for tenants.');
  }

  return blockers;
}

function buildFieldConfigurationItem(
  field: AllowedPersonalField,
): PersonalFieldConfigurationItemDto {
  const readiness = field.isSystemManaged
    ? 'SYSTEM_MANAGED'
    : field.defaultSelected
      ? 'CP_DEFAULT_SELECTED'
      : 'AVAILABLE_TO_INCLUDE';

  const requiredRule =
    field.isSystemManaged || field.minimumRequired === 'auto'
      ? 'SYSTEM_MANAGED'
      : field.minimumRequired === 'required'
        ? 'LOCKED_REQUIRED'
        : 'TENANT_CHOICE';

  return {
    familyKey: field.familyKey,
    fieldKey: field.fieldKey,
    label: field.label,
    notes: field.notes,
    minimumRequired: field.minimumRequired,
    isSystemManaged: field.isSystemManaged,
    presentationState: field.isSystemManaged ? 'READ_ONLY_SYSTEM_MANAGED' : 'CONFIGURABLE',
    readiness,
    requiredRule,
    maskingRule: field.isSystemManaged ? 'LOCKED_SYSTEM_MANAGED' : 'TENANT_CHOICE_WHEN_INCLUDED',
    canBeExcludedLater: !field.isSystemManaged && field.minimumRequired === 'none',
    canToggleRequiredLater: field.minimumRequired === 'none' && !field.isSystemManaged,
    canToggleMaskingLater: !field.isSystemManaged,
    warnings: buildFieldWarnings(field),
    blockers: buildFieldBlockers(field),
  };
}

function buildFieldConfigurationFamily(params: {
  familyKey: PersonalFamilyKey;
  label: string;
  fields: AllowedPersonalField[];
}): PersonalFieldConfigurationFamilyDto {
  const requiredFieldCount = params.fields.filter(
    (field) => field.minimumRequired === 'required',
  ).length;
  const systemManagedFieldCount = params.fields.filter((field) => field.isSystemManaged).length;
  const canExclude = requiredFieldCount === 0 && systemManagedFieldCount === 0;

  return {
    familyKey: params.familyKey,
    label: params.label,
    canExclude,
    exclusionLockedReason: canExclude
      ? null
      : requiredFieldCount > 0
        ? 'Contains minimum-required fields that cannot be excluded.'
        : 'Contains system-managed fields that keep this family visible.',
    visibleFieldCount: params.fields.length,
    defaultSelectedFieldCount: params.fields.filter((field) => field.defaultSelected).length,
    minimumRequiredFieldCount: requiredFieldCount,
    systemManagedFieldCount,
    notes: familyNotes({
      containsLockedRequiredFields: !canExclude,
      allowedFieldCount: params.fields.length,
      defaultSelectedFieldCount: params.fields.filter((field) => field.defaultSelected).length,
      systemManagedFieldKeys: params.fields
        .filter((field) => field.isSystemManaged)
        .map((field) => field.fieldKey),
    }),
    fields: params.fields.map((field) => buildFieldConfigurationItem(field)),
  };
}

export class PersonalSettingsQueryService {
  build(params: {
    sectionStatus: SettingsSetupStatus;
    version: number;
    cpRevision: number;
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
          description:
            'Field configuration is unavailable because the Personal module is disabled.',
          summary:
            'This route does not expose hidden Personal fields when the module is not allowed.',
          status: 'CURRENT_FOUNDATION',
          isLiveInCurrentRepo: true,
          hiddenVsExcluded: {
            hidden: 'Not CP-allowed fields never render in the tenant Settings surface.',
            excluded:
              'Excluded means CP-allowed but tenant-disabled. No excluded state exists while the module is disabled.',
          },
          conflictGuidance: {
            version: params.version,
            cpRevision: params.cpRevision,
            summary: 'Personal is unavailable, so no tenant-side Personal draft state exists.',
            notes: [
              'This page is versioned for honest conflict messaging only.',
              'No Personal save contract is available in the current repo state for this workspace.',
            ],
          },
          families: [],
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

    const hasExplicitFamilyAllowances = (personalAllowance?.families?.length ?? 0) > 0;

    const allowedFields = buildAllowedFields({ cpHandoff: params.cpHandoff }).filter((field) => {
      const familyAllowed = hasExplicitFamilyAllowances
        ? allowedFamilies.get(field.familyKey) === true
        : (PERSONAL_FAMILY_DEFAULTS.find((family) => family.familyKey === field.familyKey)
            ?.defaultAllowed ?? true);

      return familyAllowed && field.isAllowed;
    });

    const visibleFamilyKeys = hasExplicitFamilyAllowances
      ? PERSONAL_FAMILY_DEFAULTS.filter(
          (family) => allowedFamilies.get(family.familyKey) === true,
        ).map((family) => family.familyKey)
      : PERSONAL_FAMILY_DEFAULTS.filter((family) => family.defaultAllowed).map(
          (family) => family.familyKey,
        );

    const families = PERSONAL_FAMILY_DEFAULTS.filter((family) =>
      visibleFamilyKeys.includes(family.familyKey),
    ).map<PersonalFamilyReviewItemDto>((family) => {
      const familyFields = allowedFields.filter((field) => field.familyKey === family.familyKey);
      const requiredFieldKeys = familyFields
        .filter((field) => field.minimumRequired === 'required')
        .map((field) => field.fieldKey);
      const systemManagedFieldKeys = familyFields
        .filter((field) => field.isSystemManaged)
        .map((field) => field.fieldKey);
      const containsLockedRequiredFields =
        requiredFieldKeys.length > 0 || systemManagedFieldKeys.length > 0;

      return {
        familyKey: family.familyKey,
        label: PERSONAL_FAMILY_LABELS[family.familyKey] ?? family.label,
        reviewDecision: 'UNREVIEWED',
        reviewStatus: 'NOT_STARTED',
        allowedFieldCount: familyFields.length,
        defaultSelectedFieldCount: familyFields.filter((field) => field.defaultSelected).length,
        containsLockedRequiredFields,
        canExclude: !containsLockedRequiredFields,
        requiredFieldKeys,
        systemManagedFieldKeys,
        notes: familyNotes({
          containsLockedRequiredFields,
          allowedFieldCount: familyFields.length,
          defaultSelectedFieldCount: familyFields.filter((field) => field.defaultSelected).length,
          systemManagedFieldKeys,
        }),
      };
    });

    const fieldFamilies = PERSONAL_FAMILY_DEFAULTS.filter((family) =>
      visibleFamilyKeys.includes(family.familyKey),
    ).map((family) =>
      buildFieldConfigurationFamily({
        familyKey: family.familyKey,
        label: PERSONAL_FAMILY_LABELS[family.familyKey] ?? family.label,
        fields: allowedFields.filter((field) => field.familyKey === family.familyKey),
      }),
    );

    const warnings: string[] = [];
    const blockers: string[] = [];

    if (params.sectionStatus === 'NEEDS_REVIEW') {
      warnings.push('Platform changes require your review before Personal can return to Complete.');
    }

    if (fieldFamilies.length === 0) {
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
          'Review the real field-rule foundation. Hidden fields stay absent, system-managed fields stay read-only, and required-floor rules are already enforced at the rule layer.',
        summary:
          fieldFamilies.length === 0
            ? 'No CP-allowed fields are currently visible.'
            : `${allowedFields.length} CP-allowed fields are grouped by family. Tenant-side include, required, and masking decisions remain unsaved until the later Personal save contract ships.`,
        status: 'CURRENT_FOUNDATION',
        isLiveInCurrentRepo: true,
        hiddenVsExcluded: {
          hidden:
            'Hidden means the field is not allowed by Control Plane. Hidden fields never render in this DTO or the tenant UI.',
          excluded:
            'Excluded means the field is CP-allowed but the tenant later chooses not to use it. That tenant-owned excluded state is not persisted yet because the final Personal save contract ships later.',
        },
        conflictGuidance: {
          version: params.version,
          cpRevision: params.cpRevision,
          summary:
            'Use the current section version and CP revision as the future conflict baseline. Later Personal saves must preserve draft state on 409 and must not silently retry or discard.',
          notes: [
            'No Personal mutation route is shipped in this phase, so there is no fake save success path.',
            'If CP changes before the later save contract ships, the next read reflects the latest allowed universe immediately.',
          ],
        },
        families: fieldFamilies,
      },
      sectionBuilder: {
        key: 'sectionBuilder',
        title: 'Section Builder',
        description:
          'Default section generation and the simple section builder land after field configuration.',
        status: 'FUTURE_PHASE',
        isLiveInCurrentRepo: false,
        summary:
          'The current repo stops before section creation, rearrangement, or final Personal save semantics.',
      },
    };
  }
}
