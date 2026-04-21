/**
 * backend/src/modules/settings/services/access-settings.service.ts
 *
 * WHY:
 * - Implements the first real Settings write path for Phase 4:
 *   `POST /settings/access/acknowledge`.
 * - Keeps the write transaction explicit and scoped:
 *   validate current review state -> transition Access -> recompute aggregate -> audit success.
 * - Preserves the locked rules:
 *   acknowledge only, no generic save, no auth-scaffold substitution, no unrelated section mutation.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { AuditRepo } from '../../../shared/audit/audit.repo';
import { AppError } from '../../../shared/http/errors';
import { SettingsErrors } from '../settings.errors';
import type { AcknowledgeAccessSettingsInput } from '../settings.schemas';
import type { SettingsMutationResultDto } from '../settings.types';
import { SETTINGS_REASON_CODES } from '../settings.types';
import { SettingsReadRepo } from '../dal/settings-read.repo';
import { SettingsFoundationRepo } from '../dal/settings-foundation.repo';
import { SettingsStateService } from './settings-state.service';
import { AccessSettingsQueryService } from './access-settings-query.service';
import { IntegrationsSettingsQueryService } from './integrations-settings-query.service';
import { deriveSettingsNextAction } from './settings-next-action';
import { SettingsAuditService } from './settings-audit.service';
import type { SettingsAuditRequestContext } from '../settings.audit';

export class AccessSettingsService {
  constructor(
    private readonly deps: {
      db: DbExecutor;
      auditRepo: AuditRepo;
      readRepo: SettingsReadRepo;
      foundationRepo: SettingsFoundationRepo;
      stateService: SettingsStateService;
      accessQuery: AccessSettingsQueryService;
      integrationsQuery: IntegrationsSettingsQueryService;
      auditService: SettingsAuditService;
    },
  ) {}

  private getFailureAuditMetadata(error: unknown): { errorCode: string; message: string } {
    if (error instanceof AppError) {
      return {
        errorCode: error.code,
        message: error.message,
      };
    }

    if (error instanceof Error) {
      return {
        errorCode: 'INTERNAL',
        message: error.message,
      };
    }

    return {
      errorCode: 'INTERNAL',
      message: 'Unknown settings acknowledge failure',
    };
  }

  async acknowledgeAccess(
    auth: SettingsAuditRequestContext,
    input: AcknowledgeAccessSettingsInput,
  ): Promise<SettingsMutationResultDto> {
    try {
      return await this.deps.db.transaction().execute(async (trx) => {
        const readRepo = this.deps.readRepo.withDb(trx);
        const foundationRepo = this.deps.foundationRepo.withDb(trx);
        const stateService = this.deps.stateService.withDb(trx);
        const auditService = this.deps.auditService.withAuditRepo(this.deps.auditRepo.withDb(trx));

        const [state, tenant, cpHandoff] = await Promise.all([
          readRepo.getStateBundle(auth.tenantId),
          readRepo.getTenant(auth.tenantId),
          readRepo.getCpHandoffByTenantId(auth.tenantId),
        ]);

        if (!state) {
          throw new Error(`Settings foundation rows not found for tenant ${auth.tenantId}`);
        }

        if (!tenant) {
          throw new Error(`Tenant not found for access acknowledge: ${auth.tenantId}`);
        }

        const currentSection = state.sections.access;

        if (input.expectedCpRevision !== currentSection.appliedCpRevision) {
          throw SettingsErrors.accessSectionCpRevisionConflict();
        }

        if (input.expectedVersion !== currentSection.version) {
          throw SettingsErrors.accessSectionVersionConflict();
        }

        const access = this.deps.accessQuery.build({ tenant, cpHandoff });
        const integrations = this.deps.integrationsQuery.build({ tenant, cpHandoff });

        const googleIntegrationAllowed =
          cpHandoff?.allowances.integrations.integrations.find(
            (integration) => integration.integrationKey === 'integration.sso.google',
          )?.isAllowed ?? tenant.allowedSso.includes('google');

        const microsoftIntegrationAllowed =
          cpHandoff?.allowances.integrations.integrations.find(
            (integration) => integration.integrationKey === 'integration.sso.microsoft',
          )?.isAllowed ?? tenant.allowedSso.includes('microsoft');

        const surface = this.deps.accessQuery.buildSurface({
          access,
          googleIntegrationAllowed,
          microsoftIntegrationAllowed,
          googleIntegrationStatus: integrations.google,
          microsoftIntegrationStatus: integrations.microsoft,
        });

        if (surface.blockers.length > 0) {
          throw SettingsErrors.accessSectionBlocked(surface.blockers);
        }

        const transitionAt = new Date();

        if (currentSection.status !== 'COMPLETE') {
          await foundationRepo.transitionSectionState({
            tenantId: auth.tenantId,
            sectionKey: 'access',
            nextStatus: 'COMPLETE',
            appliedCpRevision: currentSection.appliedCpRevision,
            reasonCode: SETTINGS_REASON_CODES.ACCESS_ACKNOWLEDGED,
            transitionAt,
            actorUserId: auth.userId,
            markReviewed: true,
            markSaved: true,
          });
        }

        const refreshedSections = await foundationRepo.getStateBundle(auth.tenantId);
        if (!refreshedSections) {
          throw new Error(`Settings foundation rows not found for tenant ${auth.tenantId}`);
        }

        const personalRequired = cpHandoff?.allowances.modules.modules.personal ?? true;
        const recomputed = await stateService.recomputeAggregate({
          tenantId: auth.tenantId,
          appliedCpRevision: refreshedSections.sections.access.appliedCpRevision,
          transitionAt,
          personalRequired,
          actorUserId: auth.userId,
          reasonCode: SETTINGS_REASON_CODES.ACCESS_ACKNOWLEDGED,
        });

        const section = recomputed.sections.access;
        const aggregate = recomputed.aggregate;

        const nextAction = deriveSettingsNextAction({
          overallStatus: aggregate.overallStatus,
          accessStatus: section.status,
          personalStatus: recomputed.sections.personal.status,
          personalRequired,
        });

        const writer = auditService.buildWriter(auth);
        await auditService.recordAccessAcknowledged({
          writer,
          tenantId: auth.tenantId,
          sectionVersion: section.version,
          cpRevision: section.appliedCpRevision,
          status: section.status,
          aggregateStatus: aggregate.overallStatus,
        });

        return {
          section: {
            key: 'access',
            status: section.status,
            version: section.version,
            cpRevision: section.appliedCpRevision,
          },
          aggregate: {
            status: aggregate.overallStatus,
            version: aggregate.version,
            cpRevision: aggregate.appliedCpRevision,
            nextAction,
          },
          warnings: surface.warnings,
        };
      });
    } catch (error) {
      const failure = this.getFailureAuditMetadata(error);
      await this.deps.auditService.recordAccessAcknowledgeFailed({
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
