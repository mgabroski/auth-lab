/**
 * backend/src/modules/settings/dal/account-settings.repo.ts
 *
 * WHY:
 * - Owns the persisted tenant-side Account Settings card state introduced by
 *   the real Account implementation.
 * - Keeps per-card versioning, values, and revision alignment out of the
 *   higher-level section services.
 *
 * RULES:
 * - No AppError.
 * - Caller owns transaction boundaries and conflict checks.
 * - No aggregate recomputation here.
 */

import { sql, type Selectable } from 'kysely';

import type { DbExecutor } from '../../../shared/db/db';
import type { JsonValue, TenantAccountSettings } from '../../../shared/db/database.types';
import type {
  AccountBrandingValuesDto,
  AccountCalendarValuesDto,
  AccountOrgStructureValuesDto,
  SettingsSetupStatus,
} from '../settings.types';

type TenantAccountSettingsRow = Selectable<TenantAccountSettings>;

function asDate(value: Date | string | null): Date | null {
  if (!value) {
    return null;
  }

  return value instanceof Date ? value : new Date(value);
}

function asStatus(value: string): SettingsSetupStatus {
  return value as SettingsSetupStatus;
}

function normalizeStoredStringArray(value: JsonValue): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const out: string[] = [];
  for (const item of value) {
    if (typeof item === 'string') {
      const trimmed = item.trim();
      if (trimmed.length > 0) {
        out.push(trimmed);
      }
    }
  }

  return out;
}

export type TenantAccountSettingsRecord = {
  tenantId: string;
  branding: {
    status: SettingsSetupStatus;
    version: number;
    appliedCpRevision: number;
    lastSavedAt: Date | null;
    lastSavedByUserId: string | null;
    values: AccountBrandingValuesDto;
  };
  orgStructure: {
    status: SettingsSetupStatus;
    version: number;
    appliedCpRevision: number;
    lastSavedAt: Date | null;
    lastSavedByUserId: string | null;
    values: AccountOrgStructureValuesDto;
  };
  calendar: {
    status: SettingsSetupStatus;
    version: number;
    appliedCpRevision: number;
    lastSavedAt: Date | null;
    lastSavedByUserId: string | null;
    values: AccountCalendarValuesDto;
  };
  createdAt: Date;
  updatedAt: Date;
};

export function buildDefaultTenantAccountSettingsRecord(params: {
  tenantId: string;
  appliedCpRevision: number;
}): TenantAccountSettingsRecord {
  const now = new Date(0);

  return {
    tenantId: params.tenantId,
    branding: {
      status: 'NOT_STARTED',
      version: 1,
      appliedCpRevision: params.appliedCpRevision,
      lastSavedAt: null,
      lastSavedByUserId: null,
      values: {
        logoUrl: null,
        menuColor: null,
        fontColor: null,
        welcomeMessage: null,
      },
    },
    orgStructure: {
      status: 'NOT_STARTED',
      version: 1,
      appliedCpRevision: params.appliedCpRevision,
      lastSavedAt: null,
      lastSavedByUserId: null,
      values: {
        employers: [],
        locations: [],
      },
    },
    calendar: {
      status: 'NOT_STARTED',
      version: 1,
      appliedCpRevision: params.appliedCpRevision,
      lastSavedAt: null,
      lastSavedByUserId: null,
      values: {
        observedDates: [],
      },
    },
    createdAt: now,
    updatedAt: now,
  };
}

function mapRow(row: TenantAccountSettingsRow): TenantAccountSettingsRecord {
  const createdAt = row.created_at instanceof Date ? row.created_at : new Date(row.created_at);
  const updatedAt = row.updated_at instanceof Date ? row.updated_at : new Date(row.updated_at);

  return {
    tenantId: row.tenant_id,
    branding: {
      status: asStatus(row.branding_status),
      version: row.branding_version,
      appliedCpRevision: row.branding_applied_cp_revision,
      lastSavedAt: asDate(row.branding_last_saved_at),
      lastSavedByUserId: row.branding_last_saved_by_user_id,
      values: {
        logoUrl: row.branding_logo_url,
        menuColor: row.branding_menu_color,
        fontColor: row.branding_font_color,
        welcomeMessage: row.branding_welcome_message,
      },
    },
    orgStructure: {
      status: asStatus(row.org_structure_status),
      version: row.org_structure_version,
      appliedCpRevision: row.org_structure_applied_cp_revision,
      lastSavedAt: asDate(row.org_structure_last_saved_at),
      lastSavedByUserId: row.org_structure_last_saved_by_user_id,
      values: {
        employers: normalizeStoredStringArray(row.org_employers),
        locations: normalizeStoredStringArray(row.org_locations),
      },
    },
    calendar: {
      status: asStatus(row.calendar_status),
      version: row.calendar_version,
      appliedCpRevision: row.calendar_applied_cp_revision,
      lastSavedAt: asDate(row.calendar_last_saved_at),
      lastSavedByUserId: row.calendar_last_saved_by_user_id,
      values: {
        observedDates: normalizeStoredStringArray(row.calendar_observed_dates),
      },
    },
    createdAt,
    updatedAt,
  };
}

export class AccountSettingsRepo {
  constructor(private readonly db: DbExecutor) {}

  withDb(db: DbExecutor): AccountSettingsRepo {
    return new AccountSettingsRepo(db);
  }

  async ensureRow(params: {
    tenantId: string;
    appliedCpRevision: number;
    createdAt?: Date;
  }): Promise<void> {
    const createdAt = params.createdAt ?? new Date();

    await this.db
      .insertInto('tenant_account_settings')
      .values({
        tenant_id: params.tenantId,
        branding_applied_cp_revision: params.appliedCpRevision,
        org_structure_applied_cp_revision: params.appliedCpRevision,
        calendar_applied_cp_revision: params.appliedCpRevision,
        created_at: createdAt,
        updated_at: createdAt,
      })
      .onConflict((oc) => oc.column('tenant_id').doNothing())
      .execute();
  }

  async getByTenantId(tenantId: string): Promise<TenantAccountSettingsRecord | undefined> {
    const row = await this.db
      .selectFrom('tenant_account_settings')
      .selectAll()
      .where('tenant_id', '=', tenantId)
      .executeTakeFirst();

    return row ? mapRow(row) : undefined;
  }

  async syncAllCardRevisions(params: {
    tenantId: string;
    appliedCpRevision: number;
    syncedAt: Date;
  }): Promise<void> {
    await this.db
      .updateTable('tenant_account_settings')
      .set({
        branding_applied_cp_revision: params.appliedCpRevision,
        org_structure_applied_cp_revision: params.appliedCpRevision,
        calendar_applied_cp_revision: params.appliedCpRevision,
        updated_at: params.syncedAt,
      })
      .where('tenant_id', '=', params.tenantId)
      .execute();
  }

  async saveBranding(params: {
    tenantId: string;
    appliedCpRevision: number;
    savedAt: Date;
    actorUserId: string;
    values: AccountBrandingValuesDto;
  }): Promise<void> {
    await this.db
      .updateTable('tenant_account_settings')
      .set({
        branding_status: 'COMPLETE',
        branding_version: sql<number>`branding_version + 1`,
        branding_applied_cp_revision: params.appliedCpRevision,
        branding_last_saved_at: params.savedAt,
        branding_last_saved_by_user_id: params.actorUserId,
        branding_logo_url: params.values.logoUrl,
        branding_menu_color: params.values.menuColor,
        branding_font_color: params.values.fontColor,
        branding_welcome_message: params.values.welcomeMessage,
        updated_at: params.savedAt,
      })
      .where('tenant_id', '=', params.tenantId)
      .execute();
  }

  async saveOrgStructure(params: {
    tenantId: string;
    appliedCpRevision: number;
    savedAt: Date;
    actorUserId: string;
    values: AccountOrgStructureValuesDto;
  }): Promise<void> {
    await this.db
      .updateTable('tenant_account_settings')
      .set({
        org_structure_status: 'COMPLETE',
        org_structure_version: sql<number>`org_structure_version + 1`,
        org_structure_applied_cp_revision: params.appliedCpRevision,
        org_structure_last_saved_at: params.savedAt,
        org_structure_last_saved_by_user_id: params.actorUserId,
        org_employers: sql`${JSON.stringify(params.values.employers)}::jsonb`,
        org_locations: sql`${JSON.stringify(params.values.locations)}::jsonb`,
        updated_at: params.savedAt,
      })
      .where('tenant_id', '=', params.tenantId)
      .execute();
  }

  async saveCalendar(params: {
    tenantId: string;
    appliedCpRevision: number;
    savedAt: Date;
    actorUserId: string;
    values: AccountCalendarValuesDto;
  }): Promise<void> {
    await this.db
      .updateTable('tenant_account_settings')
      .set({
        calendar_status: 'COMPLETE',
        calendar_version: sql<number>`calendar_version + 1`,
        calendar_applied_cp_revision: params.appliedCpRevision,
        calendar_last_saved_at: params.savedAt,
        calendar_last_saved_by_user_id: params.actorUserId,
        calendar_observed_dates: sql`${JSON.stringify(params.values.observedDates)}::jsonb`,
        updated_at: params.savedAt,
      })
      .where('tenant_id', '=', params.tenantId)
      .execute();
  }
}
