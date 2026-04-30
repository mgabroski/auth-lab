/**
 * backend/src/modules/settings/dal/personal-settings.repo.ts
 *
 * WHY:
 * - Owns tenant-side persisted Personal configuration introduced by the final
 *   v1 Personal builder.
 * - Keeps full-replacement writes, saved family/field decisions, and section
 *   assignments out of higher-level orchestration services.
 *
 * RULES:
 * - No AppError.
 * - Caller owns transaction boundaries and conflict checks.
 * - No aggregate recomputation here.
 */

import { type Selectable } from 'kysely';

import type { DbExecutor } from '../../../shared/db/db';
import type {
  TenantFieldConfig,
  TenantPersonalFamilyState,
  TenantSectionFields,
  TenantSections,
} from '../../../shared/db/database.types';
import type { PersonalFamilyReviewDecision } from '../settings.types';

type TenantPersonalFamilyStateRow = Selectable<TenantPersonalFamilyState>;
type TenantFieldConfigRow = Selectable<TenantFieldConfig>;
type TenantSectionsRow = Selectable<TenantSections>;
type TenantSectionFieldsRow = Selectable<TenantSectionFields>;

function asDate(value: Date | string | null): Date | null {
  if (!value) return null;
  return value instanceof Date ? value : new Date(value);
}

export type TenantPersonalFamilyStateRecord = {
  tenantId: string;
  familyKey: string;
  reviewDecision: PersonalFamilyReviewDecision;
  appliedCpRevision: number;
  lastSavedAt: Date | null;
  lastSavedByUserId: string | null;
  createdAt: Date;
  updatedAt: Date;
};

export type TenantFieldConfigRecord = {
  tenantId: string;
  fieldKey: string;
  familyKey: string;
  included: boolean;
  required: boolean;
  masked: boolean;
  appliedCpRevision: number;
  lastSavedAt: Date | null;
  lastSavedByUserId: string | null;
  createdAt: Date;
  updatedAt: Date;
};

export type TenantSectionFieldRecord = {
  tenantId: string;
  sectionId: string;
  fieldKey: string;
  sortOrder: number;
  createdAt: Date;
};

export type TenantSectionRecord = {
  tenantId: string;
  sectionId: string;
  sectionName: string;
  sortOrder: number;
  appliedCpRevision: number;
  lastSavedAt: Date | null;
  lastSavedByUserId: string | null;
  createdAt: Date;
  updatedAt: Date;
};

export type TenantPersonalSettingsRecord = {
  families: TenantPersonalFamilyStateRecord[];
  fields: TenantFieldConfigRecord[];
  sections: TenantSectionRecord[];
  sectionFields: TenantSectionFieldRecord[];
};

function mapFamilyRow(row: TenantPersonalFamilyStateRow): TenantPersonalFamilyStateRecord {
  return {
    tenantId: row.tenant_id,
    familyKey: row.family_key,
    reviewDecision: row.review_decision as PersonalFamilyReviewDecision,
    appliedCpRevision: row.applied_cp_revision,
    lastSavedAt: asDate(row.last_saved_at),
    lastSavedByUserId: row.last_saved_by_user_id,
    createdAt: asDate(row.created_at) ?? new Date(0),
    updatedAt: asDate(row.updated_at) ?? new Date(0),
  };
}

function mapFieldRow(row: TenantFieldConfigRow): TenantFieldConfigRecord {
  return {
    tenantId: row.tenant_id,
    fieldKey: row.field_key,
    familyKey: row.family_key,
    included: row.included,
    required: row.required,
    masked: row.masked,
    appliedCpRevision: row.applied_cp_revision,
    lastSavedAt: asDate(row.last_saved_at),
    lastSavedByUserId: row.last_saved_by_user_id,
    createdAt: asDate(row.created_at) ?? new Date(0),
    updatedAt: asDate(row.updated_at) ?? new Date(0),
  };
}

function mapSectionRow(row: TenantSectionsRow): TenantSectionRecord {
  return {
    tenantId: row.tenant_id,
    sectionId: row.section_id,
    sectionName: row.section_name,
    sortOrder: row.sort_order,
    appliedCpRevision: row.applied_cp_revision,
    lastSavedAt: asDate(row.last_saved_at),
    lastSavedByUserId: row.last_saved_by_user_id,
    createdAt: asDate(row.created_at) ?? new Date(0),
    updatedAt: asDate(row.updated_at) ?? new Date(0),
  };
}

function mapSectionFieldRow(row: TenantSectionFieldsRow): TenantSectionFieldRecord {
  return {
    tenantId: row.tenant_id,
    sectionId: row.section_id,
    fieldKey: row.field_key,
    sortOrder: row.sort_order,
    createdAt: asDate(row.created_at) ?? new Date(0),
  };
}

export class PersonalSettingsRepo {
  constructor(private readonly db: DbExecutor) {}

  withDb(db: DbExecutor): PersonalSettingsRepo {
    return new PersonalSettingsRepo(db);
  }

  async getByTenantId(tenantId: string): Promise<TenantPersonalSettingsRecord> {
    const [families, fields, sections, sectionFields] = await Promise.all([
      this.db
        .selectFrom('tenant_personal_family_state')
        .selectAll()
        .where('tenant_id', '=', tenantId)
        .orderBy('family_key asc')
        .execute(),
      this.db
        .selectFrom('tenant_field_config')
        .selectAll()
        .where('tenant_id', '=', tenantId)
        .orderBy('family_key asc')
        .orderBy('field_key asc')
        .execute(),
      this.db
        .selectFrom('tenant_sections')
        .selectAll()
        .where('tenant_id', '=', tenantId)
        .orderBy('sort_order asc')
        .orderBy('section_name asc')
        .execute(),
      this.db
        .selectFrom('tenant_section_fields')
        .selectAll()
        .where('tenant_id', '=', tenantId)
        .orderBy('section_id asc')
        .orderBy('sort_order asc')
        .execute(),
    ]);

    return {
      families: families.map(mapFamilyRow),
      fields: fields.map(mapFieldRow),
      sections: sections.map(mapSectionRow),
      sectionFields: sectionFields.map(mapSectionFieldRow),
    };
  }

  async replaceConfiguration(params: {
    tenantId: string;
    appliedCpRevision: number;
    savedAt: Date;
    actorUserId: string;
    families: Array<{ familyKey: string; reviewDecision: PersonalFamilyReviewDecision }>;
    fields: Array<{
      fieldKey: string;
      familyKey: string;
      included: boolean;
      required: boolean;
      masked: boolean;
    }>;
    sections: Array<{
      sectionId: string;
      sectionName: string;
      sortOrder: number;
      fields: Array<{ fieldKey: string; sortOrder: number }>;
    }>;
  }): Promise<void> {
    await this.db
      .deleteFrom('tenant_section_fields')
      .where('tenant_id', '=', params.tenantId)
      .execute();
    await this.db.deleteFrom('tenant_sections').where('tenant_id', '=', params.tenantId).execute();
    await this.db
      .deleteFrom('tenant_field_config')
      .where('tenant_id', '=', params.tenantId)
      .execute();
    await this.db
      .deleteFrom('tenant_personal_family_state')
      .where('tenant_id', '=', params.tenantId)
      .execute();

    if (params.families.length > 0) {
      await this.db
        .insertInto('tenant_personal_family_state')
        .values(
          params.families.map((family) => ({
            tenant_id: params.tenantId,
            family_key: family.familyKey,
            review_decision: family.reviewDecision,
            applied_cp_revision: params.appliedCpRevision,
            last_saved_at: params.savedAt,
            last_saved_by_user_id: params.actorUserId,
            created_at: params.savedAt,
            updated_at: params.savedAt,
          })),
        )
        .execute();
    }

    if (params.fields.length > 0) {
      await this.db
        .insertInto('tenant_field_config')
        .values(
          params.fields.map((field) => ({
            tenant_id: params.tenantId,
            field_key: field.fieldKey,
            family_key: field.familyKey,
            included: field.included,
            required: field.required,
            masked: field.masked,
            applied_cp_revision: params.appliedCpRevision,
            last_saved_at: params.savedAt,
            last_saved_by_user_id: params.actorUserId,
            created_at: params.savedAt,
            updated_at: params.savedAt,
          })),
        )
        .execute();
    }

    if (params.sections.length > 0) {
      await this.db
        .insertInto('tenant_sections')
        .values(
          params.sections.map((section) => ({
            tenant_id: params.tenantId,
            section_id: section.sectionId,
            section_name: section.sectionName,
            sort_order: section.sortOrder,
            applied_cp_revision: params.appliedCpRevision,
            last_saved_at: params.savedAt,
            last_saved_by_user_id: params.actorUserId,
            created_at: params.savedAt,
            updated_at: params.savedAt,
          })),
        )
        .execute();

      const assignments = params.sections.flatMap((section) =>
        section.fields.map((field) => ({
          tenant_id: params.tenantId,
          section_id: section.sectionId,
          field_key: field.fieldKey,
          sort_order: field.sortOrder,
          created_at: params.savedAt,
        })),
      );

      if (assignments.length > 0) {
        await this.db.insertInto('tenant_section_fields').values(assignments).execute();
      }
    }
  }

  async syncAppliedCpRevision(params: {
    tenantId: string;
    appliedCpRevision: number;
    syncedAt: Date;
  }): Promise<void> {
    await Promise.all([
      this.db
        .updateTable('tenant_personal_family_state')
        .set({ applied_cp_revision: params.appliedCpRevision, updated_at: params.syncedAt })
        .where('tenant_id', '=', params.tenantId)
        .execute(),
      this.db
        .updateTable('tenant_field_config')
        .set({ applied_cp_revision: params.appliedCpRevision, updated_at: params.syncedAt })
        .where('tenant_id', '=', params.tenantId)
        .execute(),
      this.db
        .updateTable('tenant_sections')
        .set({ applied_cp_revision: params.appliedCpRevision, updated_at: params.syncedAt })
        .where('tenant_id', '=', params.tenantId)
        .execute(),
    ]);
  }

  async pruneToCurrentAllowance(params: {
    tenantId: string;
    appliedCpRevision: number;
    syncedAt: Date;
    allowedFamilyKeys: string[];
    allowedFieldKeys: string[];
  }): Promise<void> {
    const allowedFamilyKeys = params.allowedFamilyKeys;
    const allowedFieldKeys = params.allowedFieldKeys;

    if (allowedFieldKeys.length === 0) {
      await this.db
        .deleteFrom('tenant_section_fields')
        .where('tenant_id', '=', params.tenantId)
        .execute();
      await this.db
        .deleteFrom('tenant_sections')
        .where('tenant_id', '=', params.tenantId)
        .execute();
      await this.db
        .deleteFrom('tenant_field_config')
        .where('tenant_id', '=', params.tenantId)
        .execute();
    } else {
      await this.db
        .deleteFrom('tenant_section_fields')
        .where('tenant_id', '=', params.tenantId)
        .where('field_key', 'not in', allowedFieldKeys)
        .execute();

      await this.db
        .deleteFrom('tenant_field_config')
        .where('tenant_id', '=', params.tenantId)
        .where('field_key', 'not in', allowedFieldKeys)
        .execute();
    }

    if (allowedFamilyKeys.length === 0) {
      await this.db
        .deleteFrom('tenant_personal_family_state')
        .where('tenant_id', '=', params.tenantId)
        .execute();
    } else {
      await this.db
        .deleteFrom('tenant_personal_family_state')
        .where('tenant_id', '=', params.tenantId)
        .where('family_key', 'not in', allowedFamilyKeys)
        .execute();
    }

    const [existingSections, remainingAssignments] = await Promise.all([
      this.db
        .selectFrom('tenant_sections')
        .select('section_id')
        .where('tenant_id', '=', params.tenantId)
        .execute(),
      this.db
        .selectFrom('tenant_section_fields')
        .select('section_id')
        .where('tenant_id', '=', params.tenantId)
        .execute(),
    ]);

    const sectionIdsWithAssignments = new Set(
      remainingAssignments.map((assignment) => assignment.section_id),
    );
    const emptySectionIds = existingSections
      .map((section) => section.section_id)
      .filter((sectionId) => !sectionIdsWithAssignments.has(sectionId));

    if (emptySectionIds.length > 0) {
      await this.db
        .deleteFrom('tenant_sections')
        .where('tenant_id', '=', params.tenantId)
        .where('section_id', 'in', emptySectionIds)
        .execute();
    }

    await this.syncAppliedCpRevision({
      tenantId: params.tenantId,
      appliedCpRevision: params.appliedCpRevision,
      syncedAt: params.syncedAt,
    });
  }
}
