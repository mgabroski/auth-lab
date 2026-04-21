/**
 * backend/src/modules/settings/services/settings-evaluators.ts
 *
 * WHY:
 * - Collects the pure evaluator logic required by Step 10 Phase 2.
 * - Keeps transition rules explicit and testable outside of controller/service
 *   orchestration.
 * - Centralises the locked v1 classification model so future write surfaces do
 *   not drift from the roadmap.
 *
 * RULES:
 * - Pure functions only.
 * - No DB access, no logging, no AppError.
 * - Read composition may use derived card/status helpers, but authoritative
 *   aggregate truth must still come from persisted state updated by services.
 */

import type { CpSettingsHandoffSnapshot } from '../../control-plane/accounts/handoff/cp-settings-handoff.types';
import {
  SETTINGS_REASON_CODES,
  type SettingsReasonCode,
  type SettingsSectionKey,
  type SettingsSetupStatus,
  type SettingsStateBundle,
} from '../settings.types';

export type SetupAggregateEvaluatorInput = {
  state: SettingsStateBundle;
  personalRequired: boolean;
};

export type PersonalCompletionInput = {
  hasSavedConfiguration: boolean;
  hasReviewedAllowedFamily: boolean;
  missingRequiredFieldKeys: string[];
};

export type SsoReadinessSnapshotStatus = 'READY' | 'SNAPSHOT_UNAVAILABLE';

export type SsoReadinessSnapshot = {
  providerKey: 'google' | 'microsoft';
  status: SsoReadinessSnapshotStatus;
  asOf: Date;
  detail: string | null;
};

export type IntegrationDisplayStatus = 'HIDDEN' | 'READY' | 'NOT_IN_USE' | 'BLOCKED';

export type IntegrationStatusEvaluation = {
  integrationKey: 'integration.sso.google' | 'integration.sso.microsoft';
  displayStatus: IntegrationDisplayStatus;
  warnings: string[];
};

export type IntegrationStatusEvaluatorInput = {
  integrationKey: 'integration.sso.google' | 'integration.sso.microsoft';
  isAllowed: boolean;
  loginMethodEnabled: boolean;
  readinessSnapshot: SsoReadinessSnapshot;
};

export type NeedsReviewCascadeResult = {
  impactedSections: Array<{
    sectionKey: SettingsSectionKey;
    reasonCode: SettingsReasonCode;
  }>;
};

function statusRank(status: SettingsSetupStatus): number {
  switch (status) {
    case 'NEEDS_REVIEW':
      return 4;
    case 'COMPLETE':
      return 3;
    case 'IN_PROGRESS':
      return 2;
    case 'NOT_STARTED':
    default:
      return 1;
  }
}

export const PersonalCompletionEvaluator = {
  evaluate(input: PersonalCompletionInput): SettingsSetupStatus {
    if (
      input.hasSavedConfiguration &&
      input.hasReviewedAllowedFamily &&
      input.missingRequiredFieldKeys.length === 0
    ) {
      return 'COMPLETE';
    }

    if (input.hasSavedConfiguration || input.hasReviewedAllowedFamily) {
      return 'IN_PROGRESS';
    }

    return 'NOT_STARTED';
  },
};

export const SetupSectionEvaluator = {
  passthrough(status: SettingsSetupStatus): SettingsSetupStatus {
    return status;
  },

  fromPersonalCompletion(input: PersonalCompletionInput): SettingsSetupStatus {
    return PersonalCompletionEvaluator.evaluate(input);
  },
};

export const SetupAggregateEvaluator = {
  evaluate(input: SetupAggregateEvaluatorInput): SettingsSetupStatus {
    const gatingStatuses: SettingsSetupStatus[] = [input.state.sections.access.status];

    if (input.personalRequired) {
      gatingStatuses.push(input.state.sections.personal.status);
    }

    if (gatingStatuses.some((status) => status === 'NEEDS_REVIEW')) {
      return 'NEEDS_REVIEW';
    }

    if (gatingStatuses.every((status) => status === 'COMPLETE')) {
      return 'COMPLETE';
    }

    const allSectionStatuses = Object.values(input.state.sections).map((section) => section.status);
    const strongest = allSectionStatuses.reduce<SettingsSetupStatus>(
      (best, current) => (statusRank(current) > statusRank(best) ? current : best),
      'NOT_STARTED',
    );

    return strongest === 'NOT_STARTED' ? 'NOT_STARTED' : 'IN_PROGRESS';
  },
};

export const IntegrationStatusEvaluator = {
  evaluate(input: IntegrationStatusEvaluatorInput): IntegrationStatusEvaluation {
    if (!input.isAllowed) {
      return {
        integrationKey: input.integrationKey,
        displayStatus: 'HIDDEN',
        warnings: [],
      };
    }

    if (!input.loginMethodEnabled) {
      return {
        integrationKey: input.integrationKey,
        displayStatus: 'NOT_IN_USE',
        warnings: [],
      };
    }

    if (input.readinessSnapshot.status === 'READY') {
      return {
        integrationKey: input.integrationKey,
        displayStatus: 'READY',
        warnings: [],
      };
    }

    const providerLabel =
      input.integrationKey === 'integration.sso.google' ? 'Google' : 'Microsoft';

    return {
      integrationKey: input.integrationKey,
      displayStatus: 'BLOCKED',
      warnings: [
        `${providerLabel} SSO runtime readiness is unavailable from the cached auth/runtime snapshot. Settings GET routes do not make live provider calls.`,
      ],
    };
  },
};

function isRequiredPersonalFieldRemoval(params: {
  previous: CpSettingsHandoffSnapshot;
  next: CpSettingsHandoffSnapshot;
}): boolean {
  const previousRequiredAllowedFields = new Map(
    params.previous.allowances.personal.fields
      .filter(
        (field) =>
          field.isAllowed && (field.minimumRequired === 'required' || field.isSystemManaged),
      )
      .map((field) => [field.fieldKey, field]),
  );

  return Array.from(previousRequiredAllowedFields.keys()).some((fieldKey) => {
    const nextField = params.next.allowances.personal.fields.find(
      (field) => field.fieldKey === fieldKey,
    );
    return !nextField || !nextField.isAllowed;
  });
}

function isOptionalPersonalRemoval(params: {
  previous: CpSettingsHandoffSnapshot;
  next: CpSettingsHandoffSnapshot;
}): boolean {
  return params.previous.allowances.personal.fields.some((field) => {
    if (!field.isAllowed || field.minimumRequired !== 'none' || field.isSystemManaged) {
      return false;
    }

    const nextField = params.next.allowances.personal.fields.find(
      (candidate) => candidate.fieldKey === field.fieldKey,
    );

    return !nextField || !nextField.isAllowed;
  });
}

function accessChanged(
  previous: CpSettingsHandoffSnapshot,
  next: CpSettingsHandoffSnapshot,
): boolean {
  return JSON.stringify(previous.allowances.access) !== JSON.stringify(next.allowances.access);
}

function integrationDependencyChanged(
  previous: CpSettingsHandoffSnapshot,
  next: CpSettingsHandoffSnapshot,
): boolean {
  const previousGoogle = previous.allowances.integrations.integrations.find(
    (integration) => integration.integrationKey === 'integration.sso.google',
  )?.isAllowed;
  const nextGoogle = next.allowances.integrations.integrations.find(
    (integration) => integration.integrationKey === 'integration.sso.google',
  )?.isAllowed;
  const previousMicrosoft = previous.allowances.integrations.integrations.find(
    (integration) => integration.integrationKey === 'integration.sso.microsoft',
  )?.isAllowed;
  const nextMicrosoft = next.allowances.integrations.integrations.find(
    (integration) => integration.integrationKey === 'integration.sso.microsoft',
  )?.isAllowed;

  return (
    (previous.allowances.access.loginMethods.google && previousGoogle !== nextGoogle) ||
    (previous.allowances.access.loginMethods.microsoft && previousMicrosoft !== nextMicrosoft)
  );
}

function personalRequiredBoundaryChanged(
  previous: CpSettingsHandoffSnapshot,
  next: CpSettingsHandoffSnapshot,
): boolean {
  if (previous.allowances.modules.modules.personal !== next.allowances.modules.modules.personal) {
    return true;
  }

  return isRequiredPersonalFieldRemoval({ previous, next });
}

export const NeedsReviewCascadeEvaluator = {
  evaluate(params: {
    previous: CpSettingsHandoffSnapshot;
    next: CpSettingsHandoffSnapshot;
  }): NeedsReviewCascadeResult {
    const impactedSections: NeedsReviewCascadeResult['impactedSections'] = [];

    if (accessChanged(params.previous, params.next)) {
      impactedSections.push({
        sectionKey: 'access',
        reasonCode: SETTINGS_REASON_CODES.CP_REQUIRED_TARGET_CHANGED,
      });
    } else if (integrationDependencyChanged(params.previous, params.next)) {
      impactedSections.push({
        sectionKey: 'access',
        reasonCode: SETTINGS_REASON_CODES.CP_INTEGRATION_DEPENDENCY_CHANGED,
      });
    }

    if (personalRequiredBoundaryChanged(params.previous, params.next)) {
      impactedSections.push({
        sectionKey: 'personal',
        reasonCode:
          params.previous.allowances.modules.modules.personal &&
          !params.next.allowances.modules.modules.personal
            ? SETTINGS_REASON_CODES.CP_REQUIRED_TARGET_REMOVED
            : SETTINGS_REASON_CODES.CP_REQUIRED_TARGET_CHANGED,
      });
    }

    return { impactedSections };
  },

  hasOptionalPersonalRemoval(params: {
    previous: CpSettingsHandoffSnapshot;
    next: CpSettingsHandoffSnapshot;
  }): boolean {
    return isOptionalPersonalRemoval(params);
  },
};
