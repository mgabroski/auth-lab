/**
 * backend/src/modules/settings/services/settings-cp-cascade.service.ts
 *
 * WHY:
 * - Implements the real synchronous CP -> Settings cascade contract introduced
 *   in Step 10 Phase 2.
 * - Applies replay-safe revision alignment and only marks required surviving
 *   boundaries as NEEDS_REVIEW when the locked rules say a tenant must review
 *   again.
 * - Keeps CP allowance truth and tenant configuration truth separate while
 *   still updating persisted Settings state in the same transaction as the CP
 *   mutation.
 *
 * RULES:
 * - No background queue.
 * - Caller owns the transaction boundary.
 * - Never fake completion or fake review resets.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { CpSettingsHandoffSnapshot } from '../../control-plane/accounts/handoff/cp-settings-handoff.types';
import { SettingsFoundationRepo } from '../dal/settings-foundation.repo';
import { SETTINGS_REASON_CODES } from '../settings.types';
import { NeedsReviewCascadeEvaluator } from './settings-evaluators';
import { SettingsStateService } from './settings-state.service';

export class SettingsCpCascadeService {
  constructor(
    private readonly foundationRepo: SettingsFoundationRepo,
    private readonly stateService: SettingsStateService,
  ) {}

  withDb(db: DbExecutor): SettingsCpCascadeService {
    const foundationRepo = this.foundationRepo.withDb(db);
    return new SettingsCpCascadeService(foundationRepo, this.stateService.withDb(db));
  }

  async applyCascade(params: {
    tenantId: string;
    previous: CpSettingsHandoffSnapshot;
    next: CpSettingsHandoffSnapshot;
    actorUserId?: string | null;
    transitionAt?: Date;
  }): Promise<void> {
    const transitionAt = params.transitionAt ?? new Date();
    const targetRevision = params.next.account.cpRevision;

    await this.foundationRepo.ensureFoundationRows({
      tenantId: params.tenantId,
      appliedCpRevision: targetRevision,
      creationReasonCode: SETTINGS_REASON_CODES.CP_PROVISIONING_FOUNDATION,
      transitionAt,
    });

    const current = await this.foundationRepo.getStateBundle(params.tenantId);
    if (!current) {
      throw new Error(`Settings foundation rows not found for tenant ${params.tenantId}`);
    }

    if (current.aggregate.appliedCpRevision >= targetRevision) {
      return;
    }

    const needsReview = NeedsReviewCascadeEvaluator.evaluate({
      previous: params.previous,
      next: params.next,
    });

    const impactedMap = new Map(
      needsReview.impactedSections.map((item) => [item.sectionKey, item.reasonCode]),
    );

    for (const sectionKey of ['access', 'account', 'personal', 'integrations'] as const) {
      const currentSection = current.sections[sectionKey];
      const impactedReason = impactedMap.get(sectionKey);

      if (impactedReason && currentSection.status === 'COMPLETE') {
        await this.foundationRepo.transitionSectionState({
          tenantId: params.tenantId,
          sectionKey,
          nextStatus: 'NEEDS_REVIEW',
          appliedCpRevision: targetRevision,
          reasonCode: impactedReason,
          transitionAt,
          actorUserId: params.actorUserId ?? null,
        });
        continue;
      }

      await this.foundationRepo.syncSectionRevision({
        tenantId: params.tenantId,
        sectionKey,
        appliedCpRevision: targetRevision,
        syncedAt: transitionAt,
      });
    }

    const refreshed = await this.foundationRepo.getStateBundle(params.tenantId);
    if (!refreshed) {
      throw new Error(`Settings foundation rows not found for tenant ${params.tenantId}`);
    }

    const aggregateReasonCode =
      needsReview.impactedSections[0]?.reasonCode ?? SETTINGS_REASON_CODES.CP_REVISION_SYNC;

    await this.stateService.recomputeAggregate({
      tenantId: params.tenantId,
      appliedCpRevision: targetRevision,
      transitionAt,
      personalRequired: params.next.allowances.modules.modules.personal,
      actorUserId: params.actorUserId ?? null,
      reasonCode: aggregateReasonCode,
    });
  }
}
