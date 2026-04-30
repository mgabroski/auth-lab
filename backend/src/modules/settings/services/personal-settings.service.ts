/**
 * backend/src/modules/settings/services/personal-settings.service.ts
 *
 * WHY:
 * - Implements the final v1 Personal write path: `PUT /settings/modules/personal`.
 * - Preserves the locked rules: one canonical full-replacement save contract,
 *   backend-generated default sections on read, explicit conflict handling,
 *   and save-driven completion only.
 */

import type { AuditRepo } from '../../../shared/audit/audit.repo';
import type { DbExecutor } from '../../../shared/db/db';
import { AppError } from '../../../shared/http/errors';
import { PersonalSettingsRepo } from '../dal/personal-settings.repo';
import { SettingsReadRepo } from '../dal/settings-read.repo';
import { SettingsFoundationRepo } from '../dal/settings-foundation.repo';
import type { SavePersonalSettingsInput } from '../settings.schemas';
import { SettingsErrors } from '../settings.errors';
import { PersonalSettingsQueryService } from './personal-settings-query.service';
import { SettingsStateService } from './settings-state.service';
import { SettingsAuditService } from './settings-audit.service';
import type { SettingsAuditRequestContext } from '../settings.audit';
import type { SettingsMutationResultDto } from '../settings.types';
import { SETTINGS_REASON_CODES } from '../settings.types';
import { deriveSettingsNextAction } from './settings-next-action';
import { PersonalCompletionEvaluator } from './settings-evaluators';
import {
  PERSONAL_FIELD_CATALOG,
  type PersonalFieldCatalogEntry,
} from '../../control-plane/accounts/cp-accounts.catalog';
import type { CpSettingsHandoffSnapshot } from '../../control-plane/accounts/handoff/cp-settings-handoff.types';

function getFailureAuditMetadata(error: unknown): { errorCode: string; message: string } {
  if (error instanceof AppError) {
    return { errorCode: error.code, message: error.message };
  }
  if (error instanceof Error) {
    return { errorCode: 'INTERNAL', message: error.message };
  }
  return { errorCode: 'INTERNAL', message: 'Unknown personal settings failure' };
}

type AllowedField = PersonalFieldCatalogEntry & {
  defaultSelected: boolean;
  defaultAllowed: boolean;
};

function normalizeAllowedFamilies(cpHandoff?: CpSettingsHandoffSnapshot): string[] {
  const explicit = cpHandoff?.allowances.personal.families ?? [];
  if (explicit.length === 0) {
    return Array.from(
      new Set(
        PERSONAL_FIELD_CATALOG.filter((field) => field.defaultAllowed).map(
          (field) => field.familyKey,
        ),
      ),
    );
  }
  return explicit.filter((family) => family.isAllowed).map((family) => family.familyKey);
}

function normalizeAllowedFields(cpHandoff?: CpSettingsHandoffSnapshot): AllowedField[] {
  const explicit = cpHandoff?.allowances.personal.fields ?? [];
  if (explicit.length === 0) {
    return PERSONAL_FIELD_CATALOG.filter((field) => field.defaultAllowed);
  }

  const catalog = new Map(PERSONAL_FIELD_CATALOG.map((field) => [field.fieldKey, field]));

  return explicit
    .filter((field) => field.isAllowed)
    .map((field): AllowedField | null => {
      const entry = catalog.get(field.fieldKey);
      if (!entry) return null;

      const allowedField: AllowedField = {
        ...entry,
        defaultSelected: field.defaultSelected,
        defaultAllowed: true,
      };

      return allowedField;
    })
    .filter((field): field is AllowedField => field !== null);
}

function validatePersonalPayload(params: {
  input: SavePersonalSettingsInput;
  cpHandoff?: CpSettingsHandoffSnapshot;
}): { blockers: string[]; cpCompatibilityErrors: string[]; includedFieldKeys: string[] } {
  const allowedFamilies = normalizeAllowedFamilies(params.cpHandoff);
  const allowedFields = normalizeAllowedFields(params.cpHandoff).filter((field) =>
    allowedFamilies.includes(field.familyKey),
  );
  const familyDecisionByKey = new Map(
    params.input.families.map((family) => [family.familyKey, family.reviewDecision]),
  );
  const fieldDecisionByKey = new Map(params.input.fields.map((field) => [field.fieldKey, field]));

  const blockers: string[] = [];
  const cpCompatibilityErrors: string[] = [];

  const payloadFamilyKeys = params.input.families.map((family) => family.familyKey);
  const payloadFieldKeys = params.input.fields.map((field) => field.fieldKey);

  const uniqueFamilyKeys = new Set(payloadFamilyKeys);
  const uniqueFieldKeys = new Set(payloadFieldKeys);
  if (uniqueFamilyKeys.size !== payloadFamilyKeys.length) {
    blockers.push('Family decisions must not contain duplicates.');
  }
  if (uniqueFieldKeys.size !== payloadFieldKeys.length) {
    blockers.push('Field decisions must not contain duplicates.');
  }

  if (
    allowedFamilies.length !== payloadFamilyKeys.length ||
    allowedFamilies.some((key) => !uniqueFamilyKeys.has(key))
  ) {
    cpCompatibilityErrors.push(
      'Personal family decisions no longer match the latest allowed Personal scope.',
    );
  }
  if (
    allowedFields.length !== payloadFieldKeys.length ||
    allowedFields.some((field) => !uniqueFieldKeys.has(field.fieldKey))
  ) {
    cpCompatibilityErrors.push(
      'Personal field decisions no longer match the latest allowed Personal scope.',
    );
  }

  for (const field of allowedFields) {
    const familyDecision = familyDecisionByKey.get(field.familyKey);
    const fieldDecision = fieldDecisionByKey.get(field.fieldKey);
    if (!familyDecision || !fieldDecision) {
      continue;
    }

    const forcedIncluded = field.minimumRequired === 'required' || field.isSystemManaged;

    if (forcedIncluded && familyDecision === 'EXCLUDED') {
      cpCompatibilityErrors.push(
        `Family ${field.familyKey} cannot be excluded under the current workspace baseline.`,
      );
    }

    if (familyDecision === 'EXCLUDED' && fieldDecision.included) {
      blockers.push(`${field.label} cannot stay included when its family is excluded.`);
    }

    if (forcedIncluded && !fieldDecision.included) {
      cpCompatibilityErrors.push(
        `${field.label} must stay included under the current workspace baseline.`,
      );
    }

    if (
      (field.minimumRequired === 'required' || field.isSystemManaged) &&
      !fieldDecision.required
    ) {
      cpCompatibilityErrors.push(
        `${field.label} must stay required under the current workspace baseline.`,
      );
    }

    if (!fieldDecision.included && (fieldDecision.required || fieldDecision.masked)) {
      blockers.push(`${field.label} cannot be required or masked while excluded.`);
    }
  }

  const includedFieldKeys = params.input.fields
    .filter((field) => field.included)
    .map((field) => field.fieldKey);
  const includedFieldSet = new Set(includedFieldKeys);

  if (includedFieldKeys.length === 0) {
    blockers.push('At least one included field must be assigned to a section.');
  }

  const assignedFieldKeys: string[] = [];
  for (const section of params.input.sections) {
    if (section.name.trim().length === 0) {
      blockers.push('Every section must have a name.');
    }
    if (section.fields.length === 0) {
      blockers.push('Empty sections may not be saved.');
    }
    const sectionFieldSet = new Set<string>();
    for (const assignment of section.fields) {
      if (!includedFieldSet.has(assignment.fieldKey)) {
        blockers.push('Only included fields may be assigned to sections.');
      }
      if (sectionFieldSet.has(assignment.fieldKey)) {
        blockers.push('A field cannot appear twice in the same section.');
      }
      sectionFieldSet.add(assignment.fieldKey);
      assignedFieldKeys.push(assignment.fieldKey);
    }
  }

  const assignedFieldSet = new Set(assignedFieldKeys);
  if (assignedFieldSet.size !== assignedFieldKeys.length) {
    blockers.push('Each included field must appear in exactly one section.');
  }
  if (
    includedFieldSet.size !== assignedFieldSet.size ||
    includedFieldKeys.some((fieldKey) => !assignedFieldSet.has(fieldKey))
  ) {
    blockers.push('All included fields must be assigned to sections before saving Personal.');
  }

  return {
    blockers: Array.from(new Set(blockers)),
    cpCompatibilityErrors: Array.from(new Set(cpCompatibilityErrors)),
    includedFieldKeys,
  };
}

export class PersonalSettingsService {
  constructor(
    private readonly deps: {
      db: DbExecutor;
      auditRepo: AuditRepo;
      readRepo: SettingsReadRepo;
      foundationRepo: SettingsFoundationRepo;
      personalRepo: PersonalSettingsRepo;
      stateService: SettingsStateService;
      personalQuery: PersonalSettingsQueryService;
      auditService: SettingsAuditService;
    },
  ) {}

  async savePersonalConfiguration(
    auth: SettingsAuditRequestContext,
    input: SavePersonalSettingsInput,
  ): Promise<SettingsMutationResultDto> {
    try {
      return await this.deps.db.transaction().execute(async (trx) => {
        const readRepo = this.deps.readRepo.withDb(trx);
        const foundationRepo = this.deps.foundationRepo.withDb(trx);
        const personalRepo = this.deps.personalRepo.withDb(trx);
        const stateService = this.deps.stateService.withDb(trx);
        const auditService = this.deps.auditService.withAuditRepo(this.deps.auditRepo.withDb(trx));

        const [state, cpHandoff] = await Promise.all([
          readRepo.getStateBundle(auth.tenantId),
          readRepo.getCpHandoffByTenantId(auth.tenantId),
        ]);

        if (!state) {
          throw new Error(`Settings foundation rows not found for tenant ${auth.tenantId}`);
        }

        const moduleEnabled = cpHandoff?.allowances.modules.modules.personal ?? true;
        if (!moduleEnabled) {
          throw SettingsErrors.personalModuleUnavailable();
        }

        const currentSection = state.sections.personal;

        if (input.expectedVersion !== currentSection.version) {
          throw SettingsErrors.personalSectionVersionConflict();
        }

        const validation = validatePersonalPayload({ input, cpHandoff });
        if (
          input.expectedCpRevision !== currentSection.appliedCpRevision &&
          validation.cpCompatibilityErrors.length > 0
        ) {
          throw SettingsErrors.personalSectionCpRevisionConflict();
        }

        if (validation.cpCompatibilityErrors.length > 0 || validation.blockers.length > 0) {
          throw SettingsErrors.personalSaveValidationFailed([
            ...validation.cpCompatibilityErrors,
            ...validation.blockers,
          ]);
        }

        const allowedFieldMap = new Map(
          normalizeAllowedFields(cpHandoff).map((field) => [field.fieldKey, field]),
        );
        const savedAt = new Date();

        await personalRepo.replaceConfiguration({
          tenantId: auth.tenantId,
          appliedCpRevision: currentSection.appliedCpRevision,
          savedAt,
          actorUserId: auth.userId,
          families: input.families.map((family) => ({
            familyKey: family.familyKey,
            reviewDecision: family.reviewDecision,
          })),
          fields: input.fields.map((field) => ({
            fieldKey: field.fieldKey,
            familyKey: allowedFieldMap.get(field.fieldKey)?.familyKey ?? 'identity',
            included: field.included,
            required: field.required,
            masked: field.masked,
          })),
          sections: input.sections.map((section) => ({
            sectionId: section.sectionId,
            sectionName: section.name.trim(),
            sortOrder: section.order,
            fields: section.fields.map((field) => ({
              fieldKey: field.fieldKey,
              sortOrder: field.order,
            })),
          })),
        });

        const savedProjection = await personalRepo.getByTenantId(auth.tenantId);
        const readModel = this.deps.personalQuery.build({
          sectionStatus: currentSection.status,
          cpHandoff,
          saved: savedProjection,
        });

        const nextSectionStatus = PersonalCompletionEvaluator.evaluate({
          hasSavedConfiguration: savedProjection.families.length > 0,
          hasReviewedAllowedFamily: readModel.progress.reviewedFamiliesCount > 0,
          missingRequiredFieldKeys: readModel.fieldConfiguration.families
            .flatMap((family) => family.fields)
            .filter(
              (field) =>
                (field.minimumRequired === 'required' || field.isSystemManaged) &&
                (!field.included || !field.required),
            )
            .map((field) => field.fieldKey),
          hasValidSectionAssignments: readModel.progress.sectionAssignmentsReady,
        });

        await foundationRepo.transitionSectionState({
          tenantId: auth.tenantId,
          sectionKey: 'personal',
          nextStatus: nextSectionStatus,
          appliedCpRevision: currentSection.appliedCpRevision,
          reasonCode: SETTINGS_REASON_CODES.PERSONAL_CONFIGURATION_SAVED,
          transitionAt: savedAt,
          actorUserId: auth.userId,
          markSaved: true,
          markReviewed: true,
        });

        const recomputed = await stateService.recomputeAggregate({
          tenantId: auth.tenantId,
          appliedCpRevision: currentSection.appliedCpRevision,
          transitionAt: savedAt,
          personalRequired: true,
          actorUserId: auth.userId,
          reasonCode: SETTINGS_REASON_CODES.PERSONAL_CONFIGURATION_SAVED,
        });

        const writer = auditService.buildWriter(auth);
        await auditService.recordPersonalSaved({
          writer,
          tenantId: auth.tenantId,
          sectionVersion: recomputed.sections.personal.version,
          cpRevision: recomputed.sections.personal.appliedCpRevision,
          status: recomputed.sections.personal.status,
          aggregateStatus: recomputed.aggregate.overallStatus,
          reviewedFamiliesCount: readModel.progress.reviewedFamiliesCount,
          includedFieldCount: validation.includedFieldKeys.length,
          sectionCount: input.sections.length,
        });

        return {
          section: {
            key: 'personal',
            status: recomputed.sections.personal.status,
            version: recomputed.sections.personal.version,
            cpRevision: recomputed.sections.personal.appliedCpRevision,
          },
          aggregate: {
            status: recomputed.aggregate.overallStatus,
            version: recomputed.aggregate.version,
            cpRevision: recomputed.aggregate.appliedCpRevision,
            nextAction: deriveSettingsNextAction({
              overallStatus: recomputed.aggregate.overallStatus,
              accessStatus: recomputed.sections.access.status,
              personalStatus: recomputed.sections.personal.status,
              personalRequired: true,
            }),
          },
          warnings: readModel.warnings,
        };
      });
    } catch (error) {
      const failure = getFailureAuditMetadata(error);
      await this.deps.auditService.recordPersonalSaveFailed({
        context: auth,
        errorCode: failure.errorCode,
        message: failure.message,
        expectedVersion: input.expectedVersion,
        expectedCpRevision: input.expectedCpRevision,
      });
      throw error;
    }
  }
}
