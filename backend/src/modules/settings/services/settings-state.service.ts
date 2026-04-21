/**
 * backend/src/modules/settings/services/settings-state.service.ts
 *
 * WHY:
 * - Owns centralized aggregate recomputation for the Settings module.
 * - Keeps the persisted state-transition model explicit and reusable by future
 *   tenant write surfaces and the CP cascade service.
 * - Prevents split-commit drift where local writes and aggregate updates happen
 *   in different transactions.
 *
 * RULES:
 * - No HTTP concerns.
 * - Caller owns the transaction boundary.
 * - This service updates persisted truth; it does not compute a substitute
 *   read-time truth for controllers.
 */

import type { DbExecutor } from '../../../shared/db/db';
import { SettingsFoundationRepo } from '../dal/settings-foundation.repo';
import {
  SETTINGS_REASON_CODES,
  type SettingsReasonCode,
  type SettingsStateBundle,
} from '../settings.types';
import { SetupAggregateEvaluator } from './settings-evaluators';

export class SettingsStateService {
  constructor(private readonly foundationRepo: SettingsFoundationRepo) {}

  withDb(db: DbExecutor): SettingsStateService {
    return new SettingsStateService(this.foundationRepo.withDb(db));
  }

  async recomputeAggregate(params: {
    tenantId: string;
    appliedCpRevision: number;
    transitionAt: Date;
    personalRequired: boolean;
    actorUserId?: string | null;
    reasonCode?: SettingsReasonCode;
  }): Promise<SettingsStateBundle> {
    const state = await this.foundationRepo.getStateBundle(params.tenantId);
    if (!state) {
      throw new Error(`Settings foundation rows not found for tenant ${params.tenantId}`);
    }

    const nextStatus = SetupAggregateEvaluator.evaluate({
      state,
      personalRequired: params.personalRequired,
    });

    await this.foundationRepo.transitionAggregateState({
      tenantId: params.tenantId,
      nextStatus,
      appliedCpRevision: params.appliedCpRevision,
      reasonCode: params.reasonCode ?? SETTINGS_REASON_CODES.CP_REVISION_SYNC,
      transitionAt: params.transitionAt,
      actorUserId: params.actorUserId ?? null,
    });

    const refreshed = await this.foundationRepo.getStateBundle(params.tenantId);
    if (!refreshed) {
      throw new Error(`Settings foundation rows not found for tenant ${params.tenantId}`);
    }

    return refreshed;
  }
}
