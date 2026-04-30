/**
 * backend/src/modules/settings/services/personal-settings-query.service.ts
 *
 * WHY:
 * - Composes the final v1 Personal read model from CP allowance truth plus the
 *   persisted tenant-side Personal configuration.
 * - Keeps backend-owned default section generation, hidden-vs-excluded rules,
 *   and completion blockers explicit and testable.
 */

import {
  PERSONAL_FAMILY_DEFAULTS,
  PERSONAL_FAMILY_LABELS,
  PERSONAL_FIELD_CATALOG,
  type PersonalFamilyKey,
} from '../../control-plane/accounts/cp-accounts.catalog';
import type { CpSettingsHandoffSnapshot } from '../../control-plane/accounts/handoff/cp-settings-handoff.types';
import type { TenantPersonalSettingsRecord } from '../dal/personal-settings.repo';
import type {
  PersonalConflictGuidanceDto,
  PersonalFamilyReviewDecision,
  PersonalFamilyReviewItemDto,
  PersonalFieldConfigurationDto,
  PersonalFieldConfigurationFamilyDto,
  PersonalFieldConfigurationItemDto,
  PersonalPanelStatus,
  PersonalProgressSummaryDto,
  PersonalSectionBuilderDto,
  PersonalSectionDto,
  PersonalSettingsDto,
  SettingsSetupStatus,
} from '../settings.types';

type AllowedFamily = {
  familyKey: PersonalFamilyKey;
  label: string;
  isAllowed: boolean;
};

type AllowedField = {
  familyKey: PersonalFamilyKey;
  fieldKey: string;
  label: string;
  notes: string;
  defaultSelected: boolean;
  minimumRequired: 'none' | 'required' | 'auto';
  isSystemManaged: boolean;
};

type DraftFamilyDecision = {
  familyKey: PersonalFamilyKey;
  label: string;
  reviewDecision: PersonalFamilyReviewDecision;
  wasSaved: boolean;
  canExclude: boolean;
  lockedReason: string | null;
  notes: string[];
};

type DraftFieldDecision = {
  familyKey: PersonalFamilyKey;
  fieldKey: string;
  label: string;
  notes: string;
  minimumRequired: 'none' | 'required' | 'auto';
  isSystemManaged: boolean;
  included: boolean;
  required: boolean;
  masked: boolean;
  wasSaved: boolean;
};

type DraftSection = {
  sectionId: string;
  name: string;
  order: number;
  fields: Array<{ fieldKey: string; order: number }>;
  wasSaved: boolean;
};

export type PersonalSettingsReadModel = {
  warnings: string[];
  blockers: string[];
  progress: PersonalProgressSummaryDto;
  familyReview: PersonalSettingsDto['familyReview'];
  fieldConfiguration: PersonalFieldConfigurationDto;
  sectionBuilder: PersonalSectionBuilderDto;
  conflictGuidance: PersonalConflictGuidanceDto;
};

function familyLabel(familyKey: PersonalFamilyKey): string {
  return PERSONAL_FAMILY_LABELS[familyKey] ?? familyKey;
}

function normalizeFamilyAllowances(cpHandoff?: CpSettingsHandoffSnapshot): AllowedFamily[] {
  const explicit = new Map<PersonalFamilyKey, boolean>(
    (cpHandoff?.allowances.personal.families ?? []).map((family) => [
      family.familyKey,
      family.isAllowed,
    ]),
  );
  const hasExplicit = explicit.size > 0;

  return PERSONAL_FAMILY_DEFAULTS.filter((family) => {
    if (!hasExplicit) {
      return family.defaultAllowed;
    }
    return explicit.get(family.familyKey) === true;
  }).map((family) => ({
    familyKey: family.familyKey,
    label: familyLabel(family.familyKey),
    isAllowed: true,
  }));
}

function normalizeFieldAllowances(cpHandoff?: CpSettingsHandoffSnapshot): AllowedField[] {
  const catalogByField = new Map(PERSONAL_FIELD_CATALOG.map((field) => [field.fieldKey, field]));
  const explicit = cpHandoff?.allowances.personal.fields ?? [];

  if (explicit.length === 0) {
    return PERSONAL_FIELD_CATALOG.filter((field) => field.defaultAllowed).map((field) => ({
      familyKey: field.familyKey,
      fieldKey: field.fieldKey,
      label: field.label,
      notes: field.notes,
      defaultSelected: field.defaultSelected,
      minimumRequired: field.minimumRequired,
      isSystemManaged: field.isSystemManaged,
    }));
  }

  return explicit
    .filter((field) => field.isAllowed)
    .map((field): AllowedField | null => {
      const catalog = catalogByField.get(field.fieldKey);
      if (!catalog) {
        return null;
      }

      const allowedField: AllowedField = {
        familyKey: field.familyKey,
        fieldKey: field.fieldKey,
        label: catalog.label,
        notes: catalog.notes,
        defaultSelected: field.defaultSelected,
        minimumRequired: field.minimumRequired,
        isSystemManaged: field.isSystemManaged,
      };

      return allowedField;
    })
    .filter((field): field is AllowedField => field !== null);
}

function familyContainsLockedField(fields: AllowedField[]): boolean {
  return fields.some((field) => field.minimumRequired === 'required' || field.isSystemManaged);
}

function familyDefaultDecision(fields: AllowedField[]): PersonalFamilyReviewDecision {
  if (familyContainsLockedField(fields)) {
    return 'IN_USE';
  }

  return fields.some((field) => field.defaultSelected) ? 'IN_USE' : 'EXCLUDED';
}

function fieldDefaultDecision(
  field: AllowedField,
  reviewDecision: PersonalFamilyReviewDecision,
): DraftFieldDecision {
  const forcedIncluded = field.minimumRequired === 'required' || field.isSystemManaged;
  const included = reviewDecision === 'IN_USE' && (forcedIncluded || field.defaultSelected);

  return {
    familyKey: field.familyKey,
    fieldKey: field.fieldKey,
    label: field.label,
    notes: field.notes,
    minimumRequired: field.minimumRequired,
    isSystemManaged: field.isSystemManaged,
    included,
    required: forcedIncluded,
    masked: false,
    wasSaved: false,
  };
}

function sectionIdForFamily(familyKey: string): string {
  return `generated-${familyKey}`;
}

function buildDefaultSections(params: {
  families: DraftFamilyDecision[];
  fields: DraftFieldDecision[];
}): DraftSection[] {
  const sections: DraftSection[] = [];

  for (const family of params.families) {
    if (family.reviewDecision !== 'IN_USE') {
      continue;
    }

    const fields = params.fields
      .filter((field) => field.familyKey === family.familyKey && field.included)
      .map((field, index) => ({ fieldKey: field.fieldKey, order: index }));

    if (fields.length === 0) {
      continue;
    }

    sections.push({
      sectionId: sectionIdForFamily(family.familyKey),
      name: family.label,
      order: sections.length,
      fields,
      wasSaved: false,
    });
  }

  return sections;
}

function mergeSavedFamilies(params: {
  allowedFamilies: AllowedFamily[];
  allowedFields: AllowedField[];
  saved: TenantPersonalSettingsRecord;
}): DraftFamilyDecision[] {
  const savedByKey = new Map(params.saved.families.map((family) => [family.familyKey, family]));

  return params.allowedFamilies.map((family) => {
    const familyFields = params.allowedFields.filter(
      (field) => field.familyKey === family.familyKey,
    );
    const saved = savedByKey.get(family.familyKey);
    const canExclude = !familyContainsLockedField(familyFields);
    const lockedReason = canExclude
      ? null
      : 'This family contains required-floor or system-managed fields and must stay in use.';

    return {
      familyKey: family.familyKey,
      label: family.label,
      reviewDecision: saved?.reviewDecision ?? familyDefaultDecision(familyFields),
      wasSaved: Boolean(saved),
      canExclude,
      lockedReason,
      notes: [
        canExclude
          ? 'This family may be excluded if you do not want to use it.'
          : 'This family remains locked in use under the workspace baseline.',
      ],
    };
  });
}

function mergeSavedFields(params: {
  allowedFields: AllowedField[];
  familyDecisions: DraftFamilyDecision[];
  saved: TenantPersonalSettingsRecord;
}): DraftFieldDecision[] {
  const familyDecisionByKey = new Map(
    params.familyDecisions.map((family) => [family.familyKey, family.reviewDecision]),
  );
  const savedByKey = new Map(params.saved.fields.map((field) => [field.fieldKey, field]));

  return params.allowedFields.map((field) => {
    const reviewDecision =
      familyDecisionByKey.get(field.familyKey) ?? familyDefaultDecision([field]);
    const saved = savedByKey.get(field.fieldKey);
    const fallback = fieldDefaultDecision(field, reviewDecision);

    if (!saved) {
      return fallback;
    }

    const forcedIncluded = field.minimumRequired === 'required' || field.isSystemManaged;
    const included = reviewDecision === 'IN_USE' ? (forcedIncluded ? true : saved.included) : false;
    const required =
      field.minimumRequired === 'required' || field.isSystemManaged
        ? true
        : included
          ? saved.required
          : false;
    const masked = included && !field.isSystemManaged ? saved.masked : false;

    return {
      familyKey: field.familyKey,
      fieldKey: field.fieldKey,
      label: field.label,
      notes: field.notes,
      minimumRequired: field.minimumRequired,
      isSystemManaged: field.isSystemManaged,
      included,
      required,
      masked,
      wasSaved: true,
    };
  });
}

function mergeSavedSections(params: {
  fields: DraftFieldDecision[];
  saved: TenantPersonalSettingsRecord;
  familyDecisions: DraftFamilyDecision[];
}): DraftSection[] {
  const includedFieldKeys = new Set(
    params.fields.filter((field) => field.included).map((field) => field.fieldKey),
  );
  const defaultSections = buildDefaultSections({
    families: params.familyDecisions,
    fields: params.fields,
  });

  if (params.saved.sections.length === 0) {
    return defaultSections;
  }

  const savedFieldsBySection = new Map<string, Array<{ fieldKey: string; order: number }>>();
  for (const assignment of params.saved.sectionFields) {
    if (!includedFieldKeys.has(assignment.fieldKey)) {
      continue;
    }

    const current = savedFieldsBySection.get(assignment.sectionId) ?? [];
    current.push({ fieldKey: assignment.fieldKey, order: assignment.sortOrder });
    savedFieldsBySection.set(assignment.sectionId, current);
  }

  const sections = params.saved.sections
    .map((section) => ({
      sectionId: section.sectionId,
      name: section.sectionName,
      order: section.sortOrder,
      fields: (savedFieldsBySection.get(section.sectionId) ?? []).sort((a, b) => a.order - b.order),
      wasSaved: true,
    }))
    .filter((section) => section.fields.length > 0);

  return sections.length > 0 ? sections : defaultSections;
}

function buildSectionAssignmentsValidity(params: {
  fields: DraftFieldDecision[];
  sections: DraftSection[];
}): {
  ready: boolean;
  blockers: string[];
} {
  const blockers: string[] = [];
  const includedFields = params.fields
    .filter((field) => field.included)
    .map((field) => field.fieldKey);
  const assignedFields = params.sections.flatMap((section) =>
    section.fields.map((field) => field.fieldKey),
  );

  let structurallyValid = true;

  if (includedFields.length === 0) {
    blockers.push('No included fields are currently assigned to sections.');
    structurallyValid = false;
  }

  for (const section of params.sections) {
    if (section.name.trim().length === 0) {
      blockers.push('Every section must have a name.');
      structurallyValid = false;
      break;
    }
    if (section.fields.length === 0) {
      blockers.push('Empty sections cannot be saved.');
      structurallyValid = false;
      break;
    }
  }

  const assignedSet = new Set(assignedFields);
  if (assignedFields.length !== assignedSet.size) {
    blockers.push('Each included field must appear in exactly one section.');
    structurallyValid = false;
  }

  const includedSet = new Set(includedFields);
  if (
    includedSet.size !== assignedSet.size ||
    includedFields.some((fieldKey) => !assignedSet.has(fieldKey))
  ) {
    blockers.push('All included fields must be assigned to sections before Personal can complete.');
    structurallyValid = false;
  }

  const hasSavedAssignments =
    params.sections.length > 0 && params.sections.every((section) => section.wasSaved);

  if (structurallyValid && !hasSavedAssignments) {
    blockers.push('Section assignments still need save.');
  }

  return {
    ready: structurallyValid && hasSavedAssignments,
    blockers,
  };
}

function buildProgress(params: {
  families: DraftFamilyDecision[];
  fields: DraftFieldDecision[];
  sections: DraftSection[];
}): PersonalProgressSummaryDto {
  const reviewedFamiliesCount = params.families.filter((family) => family.wasSaved).length;
  const requiredFieldViolations = params.fields.filter(
    (field) =>
      (field.minimumRequired === 'required' || field.isSystemManaged) &&
      (!field.included || !field.required || !field.wasSaved),
  );
  const sectionValidity = buildSectionAssignmentsValidity({
    fields: params.fields,
    sections: params.sections,
  });
  const blockers: string[] = [];

  if (reviewedFamiliesCount === 0) {
    blockers.push('No family reviewed yet.');
  }

  if (requiredFieldViolations.length > 0) {
    blockers.push('Required-floor fields still need configuration.');
  }

  blockers.push(...sectionValidity.blockers);

  return {
    reviewedFamiliesCount,
    totalAllowedFamilies: params.families.length,
    requiredFieldsReady: requiredFieldViolations.length === 0,
    sectionAssignmentsReady: sectionValidity.ready,
    blockers,
  };
}

function derivePanelStatus(params: {
  sectionStatus: SettingsSetupStatus;
  progress: PersonalProgressSummaryDto;
  savedCount: number;
  ready: boolean;
}): PersonalPanelStatus {
  if (params.sectionStatus === 'NEEDS_REVIEW') {
    return 'NEEDS_REVIEW';
  }
  if (params.ready && params.sectionStatus === 'COMPLETE') {
    return 'COMPLETE';
  }
  if (params.savedCount > 0) {
    return 'IN_PROGRESS';
  }
  return 'NOT_STARTED';
}

function buildFamilyReviewItems(params: {
  families: DraftFamilyDecision[];
  fields: DraftFieldDecision[];
}): PersonalFamilyReviewItemDto[] {
  return params.families.map((family) => {
    const familyFields = params.fields.filter((field) => field.familyKey === family.familyKey);
    const requiredFieldKeys = familyFields
      .filter((field) => field.minimumRequired === 'required' || field.isSystemManaged)
      .map((field) => field.fieldKey);

    return {
      familyKey: family.familyKey,
      label: family.label,
      reviewDecision: family.reviewDecision,
      reviewStatus: family.canExclude
        ? family.wasSaved
          ? 'SAVED'
          : 'REQUIRES_SAVE'
        : family.wasSaved
          ? 'SAVED'
          : 'LOCKED_IN_USE',
      isAllowed: true,
      canExclude: family.canExclude,
      lockedReason: family.lockedReason,
      allowedFieldCount: familyFields.length,
      includedFieldCount: familyFields.filter((field) => field.included).length,
      requiredFieldKeys,
      notes: family.notes,
      warnings: family.wasSaved
        ? []
        : ['This family decision is still local until you save Personal configuration.'],
      blockers:
        family.reviewDecision === 'EXCLUDED' && !family.canExclude
          ? ['This family cannot be excluded under the current workspace baseline.']
          : [],
    };
  });
}

function buildFieldFamilies(params: {
  families: DraftFamilyDecision[];
  fields: DraftFieldDecision[];
}): PersonalFieldConfigurationFamilyDto[] {
  return params.families.map((family) => {
    const fields = params.fields.filter((field) => field.familyKey === family.familyKey);
    return {
      familyKey: family.familyKey,
      label: family.label,
      reviewDecision: family.reviewDecision,
      canExclude: family.canExclude,
      exclusionLockedReason: family.lockedReason,
      visibleFieldCount: fields.length,
      includedFieldCount: fields.filter((field) => field.included).length,
      minimumRequiredFieldCount: fields.filter((field) => field.minimumRequired === 'required')
        .length,
      systemManagedFieldCount: fields.filter((field) => field.isSystemManaged).length,
      notes: family.notes,
      fields: fields.map<PersonalFieldConfigurationItemDto>((field) => {
        const forcedIncluded = field.minimumRequired === 'required' || field.isSystemManaged;
        return {
          familyKey: field.familyKey,
          fieldKey: field.fieldKey,
          label: field.label,
          notes: field.notes,
          minimumRequired: field.minimumRequired,
          isSystemManaged: field.isSystemManaged,
          included: field.included,
          required: field.required,
          masked: field.masked,
          includeRule: forcedIncluded ? 'LOCKED_INCLUDED' : 'TENANT_CHOICE',
          requiredRule: field.isSystemManaged
            ? 'SYSTEM_MANAGED'
            : field.minimumRequired === 'required'
              ? 'LOCKED_REQUIRED'
              : 'TENANT_CHOICE',
          maskingRule: field.isSystemManaged ? 'SYSTEM_MANAGED' : 'TENANT_CHOICE',
          canToggleInclude: !forcedIncluded,
          canToggleRequired:
            !field.isSystemManaged && field.minimumRequired === 'none' && field.included,
          canToggleMasking: !field.isSystemManaged && field.included,
          warnings: field.wasSaved
            ? []
            : ['Unsaved draft decision. Save Personal Configuration to persist it.'],
          blockers:
            family.reviewDecision === 'EXCLUDED' && field.included
              ? ['Fields cannot stay included when their family is excluded.']
              : forcedIncluded && !field.included
                ? ['Required-floor and system-managed fields must stay included.']
                : [],
        };
      }),
    };
  });
}

function buildSectionBuilder(params: {
  sections: DraftSection[];
  fields: DraftFieldDecision[];
  sectionStatus: SettingsSetupStatus;
  progress: PersonalProgressSummaryDto;
}): PersonalSectionBuilderDto {
  const savedCount = params.sections.filter((section) => section.wasSaved).length;
  return {
    key: 'sectionBuilder',
    title: 'Section Builder',
    description:
      'Start from backend-generated sections, then use simple rename, reorder, field move, add, and remove controls. Empty sections cannot be saved.',
    summary:
      params.sections.length === 0
        ? 'No sections are currently ready to save.'
        : `${params.sections.length} section${params.sections.length === 1 ? '' : 's'} are ready for review and save.`,
    status: derivePanelStatus({
      sectionStatus: params.sectionStatus,
      progress: params.progress,
      savedCount,
      ready: params.progress.sectionAssignmentsReady,
    }),
    sections: params.sections
      .sort((a, b) => a.order - b.order)
      .map<PersonalSectionDto>((section) => ({
        sectionId: section.sectionId,
        name: section.name,
        order: section.order,
        fieldCount: section.fields.length,
        fields: section.fields
          .sort((a, b) => a.order - b.order)
          .map((field) => {
            const match = params.fields.find((candidate) => candidate.fieldKey === field.fieldKey)!;
            return {
              fieldKey: field.fieldKey,
              familyKey: match.familyKey,
              label: match.label,
              order: field.order,
            };
          }),
      })),
    emptySectionSaveBlocked: true,
    removeOnlyWhenEmpty: true,
  };
}

function buildConflictGuidance(): PersonalConflictGuidanceDto {
  return {
    summary:
      'If a Personal save returns a conflict, keep your local draft, refetch the latest server DTO, and decide how to reconcile before saving again.',
    notes: [
      'There is no silent auto-merge or silent retry for Personal.',
      'A stale cpRevision is accepted only when the submitted full-replacement payload is still valid under the latest allowed Personal scope.',
    ],
  };
}

export class PersonalSettingsQueryService {
  build(params: {
    sectionStatus: SettingsSetupStatus;
    cpHandoff?: CpSettingsHandoffSnapshot;
    saved: TenantPersonalSettingsRecord;
  }): PersonalSettingsReadModel {
    const moduleEnabled = params.cpHandoff?.allowances.modules.modules.personal ?? true;

    if (!moduleEnabled) {
      return {
        warnings: [],
        blockers: ['Personal is not allowed by Control Plane for this workspace.'],
        progress: {
          reviewedFamiliesCount: 0,
          totalAllowedFamilies: 0,
          requiredFieldsReady: false,
          sectionAssignmentsReady: false,
          blockers: ['Personal is not allowed by Control Plane for this workspace.'],
        },
        familyReview: {
          key: 'familyReview',
          title: 'Family Review',
          description: 'Personal is unavailable because the module is not allowed.',
          summary: 'Personal is hidden for this workspace.',
          status: 'NOT_STARTED',
          families: [],
        },
        fieldConfiguration: {
          key: 'fieldConfiguration',
          title: 'Field Configuration',
          description: 'Personal is unavailable because the module is not allowed.',
          summary: 'No field configuration is available.',
          status: 'NOT_STARTED',
          hiddenVsExcluded: {
            hidden: 'Hidden means not CP-allowed and never shown.',
            excluded: 'Excluded means CP-allowed but tenant-disabled.',
          },
          families: [],
        },
        sectionBuilder: {
          key: 'sectionBuilder',
          title: 'Section Builder',
          description: 'Personal is unavailable because the module is not allowed.',
          summary: 'No section builder is available.',
          status: 'NOT_STARTED',
          sections: [],
          emptySectionSaveBlocked: true,
          removeOnlyWhenEmpty: true,
        },
        conflictGuidance: buildConflictGuidance(),
      };
    }

    const allowedFamilies = normalizeFamilyAllowances(params.cpHandoff);
    const allowedFields = normalizeFieldAllowances(params.cpHandoff).filter((field) =>
      allowedFamilies.some((family) => family.familyKey === field.familyKey),
    );
    const familyDecisions = mergeSavedFamilies({
      allowedFamilies,
      allowedFields,
      saved: params.saved,
    });
    const fieldDecisions = mergeSavedFields({
      allowedFields,
      familyDecisions,
      saved: params.saved,
    });
    const sections = mergeSavedSections({
      fields: fieldDecisions,
      saved: params.saved,
      familyDecisions,
    });
    const progress = buildProgress({
      families: familyDecisions,
      fields: fieldDecisions,
      sections,
    });

    const warnings: string[] = [];
    if (params.sectionStatus === 'NEEDS_REVIEW') {
      warnings.push('Platform changes require your review before Personal can return to Complete.');
    }

    const familyReview = {
      key: 'familyReview' as const,
      title: 'Family Review',
      description:
        'Review each allowed family and decide whether it stays in use. Families with required-floor or system-managed fields remain locked in use.',
      summary:
        familyDecisions.length === 0
          ? 'No Personal families are currently allowed.'
          : `${progress.reviewedFamiliesCount} of ${progress.totalAllowedFamilies} allowed families have been saved.`,
      status: derivePanelStatus({
        sectionStatus: params.sectionStatus,
        progress,
        savedCount: familyDecisions.filter((family) => family.wasSaved).length,
        ready: progress.reviewedFamiliesCount > 0,
      }),
      families: buildFamilyReviewItems({ families: familyDecisions, fields: fieldDecisions }),
    };

    const fieldConfiguration = {
      key: 'fieldConfiguration' as const,
      title: 'Field Configuration',
      description:
        'Choose which allowed fields stay included, which included fields are required, and which included fields are masked. Hidden fields never render.',
      summary: progress.requiredFieldsReady
        ? 'Required-floor fields are currently configured.'
        : 'Required-floor fields still need configuration before Personal can complete.',
      status: derivePanelStatus({
        sectionStatus: params.sectionStatus,
        progress,
        savedCount: fieldDecisions.filter((field) => field.wasSaved).length,
        ready: progress.requiredFieldsReady,
      }),
      hiddenVsExcluded: {
        hidden: 'Hidden means not CP-allowed and never shown in the tenant UI.',
        excluded: 'Excluded means CP-allowed but tenant-chosen not in use.',
      },
      families: buildFieldFamilies({ families: familyDecisions, fields: fieldDecisions }),
    };

    const sectionBuilder = buildSectionBuilder({
      sections,
      fields: fieldDecisions,
      sectionStatus: params.sectionStatus,
      progress,
    });

    return {
      warnings,
      blockers: progress.blockers,
      progress,
      familyReview,
      fieldConfiguration,
      sectionBuilder,
      conflictGuidance: buildConflictGuidance(),
    };
  }

  buildDefaultDraft(params: { cpHandoff?: CpSettingsHandoffSnapshot }): {
    allowedFamilyKeys: string[];
    allowedFieldKeys: string[];
  } {
    return {
      allowedFamilyKeys: normalizeFamilyAllowances(params.cpHandoff).map(
        (family) => family.familyKey,
      ),
      allowedFieldKeys: normalizeFieldAllowances(params.cpHandoff).map((field) => field.fieldKey),
    };
  }
}
