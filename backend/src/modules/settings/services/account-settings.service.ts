/**
 * backend/src/modules/settings/services/account-settings.service.ts
 *
 * WHY:
 * - Implements the real v1 Account Settings write surfaces:
 *   `PUT /settings/account/branding`,
 *   `PUT /settings/account/org-structure`, and
 *   `PUT /settings/account/calendar`.
 * - Keeps each card save as its own explicit transactional boundary.
 * - Preserves the locked rules: Account stays non-gating, page visit is not a
 *   completion event, and per-card versioning/conflict handling is explicit.
 */

import type { AuditRepo } from '../../../shared/audit/audit.repo';
import type { DbExecutor } from '../../../shared/db/db';
import { AppError } from '../../../shared/http/errors';
import {
  AccountSettingsRepo,
  buildDefaultTenantAccountSettingsRecord,
} from '../dal/account-settings.repo';
import { SettingsReadRepo } from '../dal/settings-read.repo';
import type {
  SaveAccountBrandingInput,
  SaveAccountCalendarInput,
  SaveAccountOrgStructureInput,
} from '../settings.schemas';
import { SettingsErrors } from '../settings.errors';
import { SettingsFoundationRepo } from '../dal/settings-foundation.repo';
import { SettingsStateService } from './settings-state.service';
import type {
  AccountBrandingValuesDto,
  AccountCalendarValuesDto,
  AccountOrgStructureValuesDto,
  SettingsAccountCardKey,
  SettingsMutationResultDto,
} from '../settings.types';
import { SETTINGS_REASON_CODES } from '../settings.types';
import { AccountSettingsQueryService } from './account-settings-query.service';
import { SettingsAuditService } from './settings-audit.service';
import { deriveSettingsNextAction } from './settings-next-action';
import type { SettingsAuditRequestContext } from '../settings.audit';

function getFailureAuditMetadata(error: unknown): { errorCode: string; message: string } {
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
    message: 'Unknown account settings failure',
  };
}

export class AccountSettingsService {
  constructor(
    private readonly deps: {
      db: DbExecutor;
      auditRepo: AuditRepo;
      readRepo: SettingsReadRepo;
      foundationRepo: SettingsFoundationRepo;
      accountRepo: AccountSettingsRepo;
      stateService: SettingsStateService;
      accountQuery: AccountSettingsQueryService;
      auditService: SettingsAuditService;
    },
  ) {}

  private async saveCard(params: {
    auth: SettingsAuditRequestContext;
    cardKey: SettingsAccountCardKey;
    input: SaveAccountBrandingInput | SaveAccountOrgStructureInput | SaveAccountCalendarInput;
    sanitize: (
      allowance: ReturnType<AccountSettingsQueryService['build']>,
    ) => AccountBrandingValuesDto | AccountOrgStructureValuesDto | AccountCalendarValuesDto;
    isVisible: (allowance: ReturnType<AccountSettingsQueryService['build']>) => boolean;
    currentVersion: (account: ReturnType<typeof buildDefaultTenantAccountSettingsRecord>) => number;
    currentCpRevision: (
      account: ReturnType<typeof buildDefaultTenantAccountSettingsRecord>,
    ) => number;
    isPayloadValidUnderAllowance: (
      allowance: ReturnType<AccountSettingsQueryService['build']>,
    ) => boolean;
    save: (
      repo: AccountSettingsRepo,
      args: {
        tenantId: string;
        appliedCpRevision: number;
        savedAt: Date;
        actorUserId: string;
        values: AccountBrandingValuesDto | AccountOrgStructureValuesDto | AccountCalendarValuesDto;
      },
    ) => Promise<void>;
    reasonCode:
      | typeof SETTINGS_REASON_CODES.ACCOUNT_BRANDING_SAVED
      | typeof SETTINGS_REASON_CODES.ACCOUNT_ORG_STRUCTURE_SAVED
      | typeof SETTINGS_REASON_CODES.ACCOUNT_CALENDAR_SAVED;
    conflictFactory: () => AppError;
    cpConflictFactory: () => AppError;
  }): Promise<SettingsMutationResultDto> {
    const failureCardKey = params.cardKey;
    const failureInput = params.input;

    try {
      return await this.deps.db.transaction().execute(async (trx) => {
        const readRepo = this.deps.readRepo.withDb(trx);
        const foundationRepo = this.deps.foundationRepo.withDb(trx);
        const accountRepo = this.deps.accountRepo.withDb(trx);
        const stateService = this.deps.stateService.withDb(trx);
        const auditService = this.deps.auditService.withAuditRepo(this.deps.auditRepo.withDb(trx));

        const [state, cpHandoff] = await Promise.all([
          readRepo.getStateBundle(params.auth.tenantId),
          readRepo.getCpHandoffByTenantId(params.auth.tenantId),
        ]);

        if (!state) {
          throw new Error(`Settings foundation rows not found for tenant ${params.auth.tenantId}`);
        }

        await accountRepo.ensureRow({
          tenantId: params.auth.tenantId,
          appliedCpRevision: state.sections.account.appliedCpRevision,
          createdAt: new Date(),
        });

        const allowance = this.deps.accountQuery.build({ cpHandoff });
        if (!this.deps.accountQuery.hasVisibleCards(allowance) || !params.isVisible(allowance)) {
          throw SettingsErrors.accountCardUnavailable(params.cardKey);
        }

        const account =
          (await accountRepo.getByTenantId(params.auth.tenantId)) ??
          buildDefaultTenantAccountSettingsRecord({
            tenantId: params.auth.tenantId,
            appliedCpRevision: state.sections.account.appliedCpRevision,
          });

        const currentVersion = params.currentVersion(account);
        const currentCpRevision = params.currentCpRevision(account);

        if (params.input.expectedVersion !== currentVersion) {
          throw params.conflictFactory();
        }

        if (
          params.input.expectedCpRevision !== currentCpRevision &&
          !params.isPayloadValidUnderAllowance(allowance)
        ) {
          throw params.cpConflictFactory();
        }

        const savedAt = new Date();
        const sanitizedValues = params.sanitize(allowance);

        await params.save(accountRepo, {
          tenantId: params.auth.tenantId,
          appliedCpRevision: currentCpRevision,
          savedAt,
          actorUserId: params.auth.userId,
          values: sanitizedValues,
        });

        const refreshedAccount = await accountRepo.getByTenantId(params.auth.tenantId);
        if (!refreshedAccount) {
          throw new Error(`Account settings row not found for tenant ${params.auth.tenantId}`);
        }

        const sectionStatus = this.deps.accountQuery.deriveSectionStatus({
          model: allowance,
          brandingStatus: refreshedAccount.branding.status,
          orgStructureStatus: refreshedAccount.orgStructure.status,
          calendarStatus: refreshedAccount.calendar.status,
        });

        await foundationRepo.transitionSectionState({
          tenantId: params.auth.tenantId,
          sectionKey: 'account',
          nextStatus: sectionStatus,
          appliedCpRevision: currentCpRevision,
          reasonCode: params.reasonCode,
          transitionAt: savedAt,
          actorUserId: params.auth.userId,
          markSaved: true,
        });

        const personalRequired = cpHandoff?.allowances.modules.modules.personal ?? true;
        const recomputed = await stateService.recomputeAggregate({
          tenantId: params.auth.tenantId,
          appliedCpRevision: currentCpRevision,
          transitionAt: savedAt,
          personalRequired,
          actorUserId: params.auth.userId,
          reasonCode: params.reasonCode,
        });

        const nextAction = deriveSettingsNextAction({
          overallStatus: recomputed.aggregate.overallStatus,
          accessStatus: recomputed.sections.access.status,
          personalStatus: recomputed.sections.personal.status,
          personalRequired,
        });

        const cardSummary =
          params.cardKey === 'branding'
            ? refreshedAccount.branding
            : params.cardKey === 'orgStructure'
              ? refreshedAccount.orgStructure
              : refreshedAccount.calendar;

        const writer = auditService.buildWriter(params.auth);
        await auditService.recordAccountCardSaved({
          writer,
          tenantId: params.auth.tenantId,
          cardKey: params.cardKey,
          cardVersion: cardSummary.version,
          sectionVersion: recomputed.sections.account.version,
          cpRevision: cardSummary.appliedCpRevision,
          sectionStatus: recomputed.sections.account.status,
          aggregateStatus: recomputed.aggregate.overallStatus,
        });

        return {
          section: {
            key: 'account',
            status: recomputed.sections.account.status,
            version: recomputed.sections.account.version,
            cpRevision: recomputed.sections.account.appliedCpRevision,
          },
          card: {
            key: params.cardKey,
            status: cardSummary.status,
            version: cardSummary.version,
            cpRevision: cardSummary.appliedCpRevision,
          },
          aggregate: {
            status: recomputed.aggregate.overallStatus,
            version: recomputed.aggregate.version,
            cpRevision: recomputed.aggregate.appliedCpRevision,
            nextAction,
          },
          warnings: [],
        };
      });
    } catch (error) {
      const failure = getFailureAuditMetadata(error);
      await this.deps.auditService.recordAccountCardSaveFailed({
        context: params.auth,
        cardKey: failureCardKey,
        errorCode: failure.errorCode,
        message: failure.message,
        expectedVersion: failureInput.expectedVersion,
        expectedCpRevision: failureInput.expectedCpRevision,
      });
      throw error;
    }
  }

  async saveBranding(
    auth: SettingsAuditRequestContext,
    input: SaveAccountBrandingInput,
  ): Promise<SettingsMutationResultDto> {
    return this.saveCard({
      auth,
      cardKey: 'branding',
      input,
      sanitize: (allowance) =>
        this.deps.accountQuery.sanitizeBrandingValues(input.values, allowance),
      isVisible: (allowance) => this.deps.accountQuery.isBrandingVisible(allowance),
      currentVersion: (account) => account.branding.version,
      currentCpRevision: (account) => account.branding.appliedCpRevision,
      isPayloadValidUnderAllowance: (allowance) =>
        this.deps.accountQuery.isBrandingPayloadValidUnderAllowance(input.values, allowance),
      save: (repo, args) =>
        repo.saveBranding({
          tenantId: args.tenantId,
          appliedCpRevision: args.appliedCpRevision,
          savedAt: args.savedAt,
          actorUserId: args.actorUserId,
          values: args.values as AccountBrandingValuesDto,
        }),
      reasonCode: SETTINGS_REASON_CODES.ACCOUNT_BRANDING_SAVED,
      conflictFactory: () => SettingsErrors.accountCardVersionConflict('branding'),
      cpConflictFactory: () => SettingsErrors.accountCardCpRevisionConflict('branding'),
    });
  }

  async saveOrgStructure(
    auth: SettingsAuditRequestContext,
    input: SaveAccountOrgStructureInput,
  ): Promise<SettingsMutationResultDto> {
    return this.saveCard({
      auth,
      cardKey: 'orgStructure',
      input,
      sanitize: (allowance) =>
        this.deps.accountQuery.sanitizeOrgStructureValues(input.values, allowance),
      isVisible: (allowance) => this.deps.accountQuery.isOrgStructureVisible(allowance),
      currentVersion: (account) => account.orgStructure.version,
      currentCpRevision: (account) => account.orgStructure.appliedCpRevision,
      isPayloadValidUnderAllowance: (allowance) =>
        this.deps.accountQuery.isOrgStructurePayloadValidUnderAllowance(input.values, allowance),
      save: (repo, args) =>
        repo.saveOrgStructure({
          tenantId: args.tenantId,
          appliedCpRevision: args.appliedCpRevision,
          savedAt: args.savedAt,
          actorUserId: args.actorUserId,
          values: args.values as AccountOrgStructureValuesDto,
        }),
      reasonCode: SETTINGS_REASON_CODES.ACCOUNT_ORG_STRUCTURE_SAVED,
      conflictFactory: () => SettingsErrors.accountCardVersionConflict('orgStructure'),
      cpConflictFactory: () => SettingsErrors.accountCardCpRevisionConflict('orgStructure'),
    });
  }

  async saveCalendar(
    auth: SettingsAuditRequestContext,
    input: SaveAccountCalendarInput,
  ): Promise<SettingsMutationResultDto> {
    return this.saveCard({
      auth,
      cardKey: 'calendar',
      input,
      sanitize: (allowance) =>
        this.deps.accountQuery.sanitizeCalendarValues(input.values, allowance),
      isVisible: (allowance) => allowance.companyCalendar.allowed,
      currentVersion: (account) => account.calendar.version,
      currentCpRevision: (account) => account.calendar.appliedCpRevision,
      isPayloadValidUnderAllowance: (allowance) =>
        this.deps.accountQuery.isCalendarPayloadValidUnderAllowance(input.values, allowance),
      save: (repo, args) =>
        repo.saveCalendar({
          tenantId: args.tenantId,
          appliedCpRevision: args.appliedCpRevision,
          savedAt: args.savedAt,
          actorUserId: args.actorUserId,
          values: args.values as AccountCalendarValuesDto,
        }),
      reasonCode: SETTINGS_REASON_CODES.ACCOUNT_CALENDAR_SAVED,
      conflictFactory: () => SettingsErrors.accountCardVersionConflict('calendar'),
      cpConflictFactory: () => SettingsErrors.accountCardCpRevisionConflict('calendar'),
    });
  }
}
