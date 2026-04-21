/**
 * backend/src/modules/settings/dal/settings-foundation.repo.ts
 *
 * WHY:
 * - Owns the low-level persistence primitives for the Settings foundation
 *   schema.
 * - Keeps rollout-bridge writes and foundational row creation out of auth and
 *   Control Plane business logic.
 * - Gives later Settings services a clean, already-tested DAL surface to build
 *   on.
 *
 * RULES:
 * - No AppError.
 * - No transactions started here.
 * - No read-time recomputation of setup truth.
 * - Writes are conservative: foundation creation inserts missing rows only,
 *   and the legacy-auth bridge only upgrades the specific NOT_STARTED states it
 *   is allowed to strengthen.
 */

import { sql, type Selectable } from 'kysely';

import type { DbExecutor } from '../../../shared/db/db';
import type { TenantSetupSectionState, TenantSetupState } from '../../../shared/db/database.types';
import {
  LIVE_SETTINGS_SECTION_KEYS,
  SETTINGS_REASON_CODES,
  type SettingsReasonCode,
  type SettingsSectionKey,
  type SettingsSetupStatus,
  type TenantSetupSectionStateRecord,
  type TenantSetupStateRecord,
} from '../settings.types';

type TenantSetupStateRow = Selectable<TenantSetupState>;
type TenantSetupSectionStateRow = Selectable<TenantSetupSectionState>;

function asDate(value: Date | string): Date {
  return value instanceof Date ? value : new Date(value);
}

function asSettingsSetupStatus(value: string): SettingsSetupStatus {
  return value as SettingsSetupStatus;
}

function mapAggregateRow(row: TenantSetupStateRow): TenantSetupStateRecord {
  return {
    tenantId: row.tenant_id,
    overallStatus: asSettingsSetupStatus(row.overall_status),
    version: row.version,
    appliedCpRevision: row.applied_cp_revision,
    lastTransitionReasonCode: row.last_transition_reason_code,
    lastTransitionAt: asDate(row.last_transition_at),
    lastSavedAt: row.last_saved_at ? asDate(row.last_saved_at) : null,
    lastSavedByUserId: row.last_saved_by_user_id,
    lastReviewedAt: row.last_reviewed_at ? asDate(row.last_reviewed_at) : null,
    lastReviewedByUserId: row.last_reviewed_by_user_id,
    createdAt: asDate(row.created_at),
    updatedAt: asDate(row.updated_at),
  };
}

function mapSectionRow(row: TenantSetupSectionStateRow): TenantSetupSectionStateRecord {
  return {
    tenantId: row.tenant_id,
    sectionKey: row.section_key as SettingsSectionKey,
    status: asSettingsSetupStatus(row.status),
    version: row.version,
    appliedCpRevision: row.applied_cp_revision,
    lastTransitionReasonCode: row.last_transition_reason_code,
    lastTransitionAt: asDate(row.last_transition_at),
    lastSavedAt: row.last_saved_at ? asDate(row.last_saved_at) : null,
    lastSavedByUserId: row.last_saved_by_user_id,
    lastReviewedAt: row.last_reviewed_at ? asDate(row.last_reviewed_at) : null,
    lastReviewedByUserId: row.last_reviewed_by_user_id,
    createdAt: asDate(row.created_at),
    updatedAt: asDate(row.updated_at),
  };
}

export class SettingsFoundationRepo {
  constructor(private readonly db: DbExecutor) {}

  withDb(db: DbExecutor): SettingsFoundationRepo {
    return new SettingsFoundationRepo(db);
  }

  async findCurrentCpRevisionForTenant(tenantId: string): Promise<number> {
    const row = await this.db
      .selectFrom('cp_account_provisioning as provisioning')
      .innerJoin('cp_accounts as account', 'account.id', 'provisioning.account_id')
      .select('account.cp_revision as cp_revision')
      .where('provisioning.tenant_id', '=', tenantId)
      .executeTakeFirst();

    return row?.cp_revision ?? 0;
  }

  async ensureFoundationRows(params: {
    tenantId: string;
    appliedCpRevision: number;
    creationReasonCode: SettingsReasonCode;
    transitionAt?: Date;
  }): Promise<void> {
    const transitionAt = params.transitionAt ?? new Date();

    await this.db
      .insertInto('tenant_setup_state')
      .values({
        tenant_id: params.tenantId,
        overall_status: 'NOT_STARTED',
        version: 1,
        applied_cp_revision: params.appliedCpRevision,
        last_transition_reason_code: params.creationReasonCode,
        last_transition_at: transitionAt,
      })
      .onConflict((oc) => oc.column('tenant_id').doNothing())
      .execute();

    await this.db
      .insertInto('tenant_setup_section_state')
      .values(
        LIVE_SETTINGS_SECTION_KEYS.map((sectionKey) => ({
          tenant_id: params.tenantId,
          section_key: sectionKey,
          status: 'NOT_STARTED',
          version: 1,
          applied_cp_revision: params.appliedCpRevision,
          last_transition_reason_code: params.creationReasonCode,
          last_transition_at: transitionAt,
        })),
      )
      .onConflict((oc) => oc.columns(['tenant_id', 'section_key']).doNothing())
      .execute();
  }

  async bridgeLegacyWorkspaceAck(params: {
    tenantId: string;
    acknowledgedAt: Date;
    appliedCpRevision: number;
    actorUserId: string;
  }): Promise<void> {
    await this.db
      .updateTable('tenant_setup_state')
      .set({
        overall_status: 'IN_PROGRESS',
        version: sql<number>`version + 1`,
        applied_cp_revision: params.appliedCpRevision,
        last_transition_reason_code: SETTINGS_REASON_CODES.LEGACY_AUTH_ACK_BRIDGE,
        last_transition_at: params.acknowledgedAt,
        updated_at: params.acknowledgedAt,
      })
      .where('tenant_id', '=', params.tenantId)
      .where('overall_status', '=', 'NOT_STARTED')
      .execute();

    await this.db
      .updateTable('tenant_setup_section_state')
      .set({
        status: 'COMPLETE',
        version: sql<number>`version + 1`,
        applied_cp_revision: params.appliedCpRevision,
        last_transition_reason_code: SETTINGS_REASON_CODES.LEGACY_AUTH_ACK_BRIDGE,
        last_transition_at: params.acknowledgedAt,
        last_reviewed_at: params.acknowledgedAt,
        last_reviewed_by_user_id: params.actorUserId,
        updated_at: params.acknowledgedAt,
      })
      .where('tenant_id', '=', params.tenantId)
      .where('section_key', '=', 'access')
      .where('status', '=', 'NOT_STARTED')
      .execute();
  }

  async findAggregateState(tenantId: string): Promise<TenantSetupStateRecord | undefined> {
    const row = await this.db
      .selectFrom('tenant_setup_state')
      .selectAll()
      .where('tenant_id', '=', tenantId)
      .executeTakeFirst();

    return row ? mapAggregateRow(row) : undefined;
  }

  async listSectionStates(tenantId: string): Promise<TenantSetupSectionStateRecord[]> {
    const rows = await this.db
      .selectFrom('tenant_setup_section_state')
      .selectAll()
      .where('tenant_id', '=', tenantId)
      .orderBy('section_key asc')
      .execute();

    return rows.map((row) => mapSectionRow(row));
  }
}
