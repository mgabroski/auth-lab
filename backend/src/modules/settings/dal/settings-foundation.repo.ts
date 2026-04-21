/**
 * backend/src/modules/settings/dal/settings-foundation.repo.ts
 *
 * WHY:
 * - Owns the low-level persistence primitives for the Settings foundation
 *   schema.
 * - Keeps rollout-bridge writes, transition-safe state updates, and revision
 *   alignment out of auth, Control Plane, and future tenant write logic.
 * - Gives the Phase 2 state engine one typed DAL surface for aggregate and
 *   section transitions without introducing DB-trigger logic.
 *
 * RULES:
 * - No AppError.
 * - No transactions started here.
 * - No read-time recomputation of setup truth.
 * - Writes are explicit: the caller decides whether a transition or a pure
 *   cpRevision sync is warranted.
 */

import { sql, type Selectable } from 'kysely';

import type { DbExecutor } from '../../../shared/db/db';
import type { TenantSetupSectionState, TenantSetupState } from '../../../shared/db/database.types';
import {
  LIVE_SETTINGS_SECTION_KEYS,
  SETTINGS_REASON_CODES,
  type SettingsAggregateRevisionSyncInput,
  type SettingsAggregateTransitionInput,
  type SettingsReasonCode,
  type SettingsSectionKey,
  type SettingsSectionRevisionSyncInput,
  type SettingsSectionTransitionInput,
  type SettingsSetupStatus,
  type SettingsStateBundle,
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

function shouldMarkSave(current: Date | null, requested: boolean | undefined): boolean {
  return requested === true || current !== null;
}

function shouldMarkReview(current: Date | null, requested: boolean | undefined): boolean {
  return requested === true || current !== null;
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

  async getSectionState(
    tenantId: string,
    sectionKey: SettingsSectionKey,
  ): Promise<TenantSetupSectionStateRecord | undefined> {
    const row = await this.db
      .selectFrom('tenant_setup_section_state')
      .selectAll()
      .where('tenant_id', '=', tenantId)
      .where('section_key', '=', sectionKey)
      .executeTakeFirst();

    return row ? mapSectionRow(row) : undefined;
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

  async getStateBundle(tenantId: string): Promise<SettingsStateBundle | undefined> {
    const aggregate = await this.findAggregateState(tenantId);
    if (!aggregate) {
      return undefined;
    }

    const sections = await this.listSectionStates(tenantId);
    const sectionMap = Object.fromEntries(
      sections.map((section) => [section.sectionKey, section]),
    ) as Record<SettingsSectionKey, TenantSetupSectionStateRecord>;

    return {
      aggregate,
      sections: sectionMap,
    };
  }

  async transitionSectionState(params: SettingsSectionTransitionInput): Promise<void> {
    const current = await this.getSectionState(params.tenantId, params.sectionKey);
    if (!current) return;

    const nextLastSavedAt = shouldMarkSave(current.lastSavedAt, params.markSaved)
      ? params.transitionAt
      : current.lastSavedAt;
    const nextLastSavedBy = shouldMarkSave(current.lastSavedAt, params.markSaved)
      ? (params.actorUserId ?? current.lastSavedByUserId ?? null)
      : current.lastSavedByUserId;
    const nextLastReviewedAt = shouldMarkReview(current.lastReviewedAt, params.markReviewed)
      ? params.transitionAt
      : current.lastReviewedAt;
    const nextLastReviewedBy = shouldMarkReview(current.lastReviewedAt, params.markReviewed)
      ? (params.actorUserId ?? current.lastReviewedByUserId ?? null)
      : current.lastReviewedByUserId;

    const changed =
      current.status !== params.nextStatus ||
      current.appliedCpRevision !== params.appliedCpRevision ||
      current.lastTransitionReasonCode !== params.reasonCode ||
      current.lastTransitionAt.getTime() !== params.transitionAt.getTime() ||
      (nextLastSavedAt?.getTime() ?? 0) !== (current.lastSavedAt?.getTime() ?? 0) ||
      (nextLastReviewedAt?.getTime() ?? 0) !== (current.lastReviewedAt?.getTime() ?? 0) ||
      nextLastSavedBy !== current.lastSavedByUserId ||
      nextLastReviewedBy !== current.lastReviewedByUserId;

    if (!changed) return;

    await this.db
      .updateTable('tenant_setup_section_state')
      .set({
        status: params.nextStatus,
        version: sql<number>`version + 1`,
        applied_cp_revision: params.appliedCpRevision,
        last_transition_reason_code: params.reasonCode,
        last_transition_at: params.transitionAt,
        last_saved_at: nextLastSavedAt,
        last_saved_by_user_id: nextLastSavedBy,
        last_reviewed_at: nextLastReviewedAt,
        last_reviewed_by_user_id: nextLastReviewedBy,
        updated_at: params.transitionAt,
      })
      .where('tenant_id', '=', params.tenantId)
      .where('section_key', '=', params.sectionKey)
      .execute();
  }

  async transitionAggregateState(params: SettingsAggregateTransitionInput): Promise<void> {
    const current = await this.findAggregateState(params.tenantId);
    if (!current) return;

    const nextLastSavedAt = shouldMarkSave(current.lastSavedAt, params.markSaved)
      ? params.transitionAt
      : current.lastSavedAt;
    const nextLastSavedBy = shouldMarkSave(current.lastSavedAt, params.markSaved)
      ? (params.actorUserId ?? current.lastSavedByUserId ?? null)
      : current.lastSavedByUserId;
    const nextLastReviewedAt = shouldMarkReview(current.lastReviewedAt, params.markReviewed)
      ? params.transitionAt
      : current.lastReviewedAt;
    const nextLastReviewedBy = shouldMarkReview(current.lastReviewedAt, params.markReviewed)
      ? (params.actorUserId ?? current.lastReviewedByUserId ?? null)
      : current.lastReviewedByUserId;

    const changed =
      current.overallStatus !== params.nextStatus ||
      current.appliedCpRevision !== params.appliedCpRevision ||
      current.lastTransitionReasonCode !== params.reasonCode ||
      current.lastTransitionAt.getTime() !== params.transitionAt.getTime() ||
      (nextLastSavedAt?.getTime() ?? 0) !== (current.lastSavedAt?.getTime() ?? 0) ||
      (nextLastReviewedAt?.getTime() ?? 0) !== (current.lastReviewedAt?.getTime() ?? 0) ||
      nextLastSavedBy !== current.lastSavedByUserId ||
      nextLastReviewedBy !== current.lastReviewedByUserId;

    if (!changed) return;

    await this.db
      .updateTable('tenant_setup_state')
      .set({
        overall_status: params.nextStatus,
        version: sql<number>`version + 1`,
        applied_cp_revision: params.appliedCpRevision,
        last_transition_reason_code: params.reasonCode,
        last_transition_at: params.transitionAt,
        last_saved_at: nextLastSavedAt,
        last_saved_by_user_id: nextLastSavedBy,
        last_reviewed_at: nextLastReviewedAt,
        last_reviewed_by_user_id: nextLastReviewedBy,
        updated_at: params.transitionAt,
      })
      .where('tenant_id', '=', params.tenantId)
      .execute();
  }

  async syncSectionRevision(params: SettingsSectionRevisionSyncInput): Promise<void> {
    const current = await this.getSectionState(params.tenantId, params.sectionKey);
    if (!current || current.appliedCpRevision === params.appliedCpRevision) {
      return;
    }

    await this.db
      .updateTable('tenant_setup_section_state')
      .set({
        version: sql<number>`version + 1`,
        applied_cp_revision: params.appliedCpRevision,
        updated_at: params.syncedAt,
      })
      .where('tenant_id', '=', params.tenantId)
      .where('section_key', '=', params.sectionKey)
      .execute();
  }

  async syncAggregateRevision(params: SettingsAggregateRevisionSyncInput): Promise<void> {
    const current = await this.findAggregateState(params.tenantId);
    if (!current || current.appliedCpRevision === params.appliedCpRevision) {
      return;
    }

    await this.db
      .updateTable('tenant_setup_state')
      .set({
        version: sql<number>`version + 1`,
        applied_cp_revision: params.appliedCpRevision,
        updated_at: params.syncedAt,
      })
      .where('tenant_id', '=', params.tenantId)
      .execute();
  }
}
