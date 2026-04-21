import { describe, expect, it } from 'vitest';

import {
  IntegrationStatusEvaluator,
  NeedsReviewCascadeEvaluator,
  SetupAggregateEvaluator,
} from '../../../src/modules/settings/services/settings-evaluators';
import type { SettingsStateBundle } from '../../../src/modules/settings/settings.types';
import type { CpSettingsHandoffSnapshot } from '../../../src/modules/control-plane/accounts/handoff/cp-settings-handoff.types';

function buildStateBundle(overrides?: Partial<SettingsStateBundle>): SettingsStateBundle {
  const base: SettingsStateBundle = {
    aggregate: {
      tenantId: 'tenant-1',
      overallStatus: 'NOT_STARTED',
      version: 1,
      appliedCpRevision: 0,
      lastTransitionReasonCode: 'FOUNDATION_INITIALIZED',
      lastTransitionAt: new Date('2026-04-21T00:00:00.000Z'),
      lastSavedAt: null,
      lastSavedByUserId: null,
      lastReviewedAt: null,
      lastReviewedByUserId: null,
      createdAt: new Date('2026-04-21T00:00:00.000Z'),
      updatedAt: new Date('2026-04-21T00:00:00.000Z'),
    },
    sections: {
      access: {
        tenantId: 'tenant-1',
        sectionKey: 'access',
        status: 'NOT_STARTED',
        version: 1,
        appliedCpRevision: 0,
        lastTransitionReasonCode: 'FOUNDATION_INITIALIZED',
        lastTransitionAt: new Date('2026-04-21T00:00:00.000Z'),
        lastSavedAt: null,
        lastSavedByUserId: null,
        lastReviewedAt: null,
        lastReviewedByUserId: null,
        createdAt: new Date('2026-04-21T00:00:00.000Z'),
        updatedAt: new Date('2026-04-21T00:00:00.000Z'),
      },
      account: {
        tenantId: 'tenant-1',
        sectionKey: 'account',
        status: 'NOT_STARTED',
        version: 1,
        appliedCpRevision: 0,
        lastTransitionReasonCode: 'FOUNDATION_INITIALIZED',
        lastTransitionAt: new Date('2026-04-21T00:00:00.000Z'),
        lastSavedAt: null,
        lastSavedByUserId: null,
        lastReviewedAt: null,
        lastReviewedByUserId: null,
        createdAt: new Date('2026-04-21T00:00:00.000Z'),
        updatedAt: new Date('2026-04-21T00:00:00.000Z'),
      },
      personal: {
        tenantId: 'tenant-1',
        sectionKey: 'personal',
        status: 'NOT_STARTED',
        version: 1,
        appliedCpRevision: 0,
        lastTransitionReasonCode: 'FOUNDATION_INITIALIZED',
        lastTransitionAt: new Date('2026-04-21T00:00:00.000Z'),
        lastSavedAt: null,
        lastSavedByUserId: null,
        lastReviewedAt: null,
        lastReviewedByUserId: null,
        createdAt: new Date('2026-04-21T00:00:00.000Z'),
        updatedAt: new Date('2026-04-21T00:00:00.000Z'),
      },
      integrations: {
        tenantId: 'tenant-1',
        sectionKey: 'integrations',
        status: 'NOT_STARTED',
        version: 1,
        appliedCpRevision: 0,
        lastTransitionReasonCode: 'FOUNDATION_INITIALIZED',
        lastTransitionAt: new Date('2026-04-21T00:00:00.000Z'),
        lastSavedAt: null,
        lastSavedByUserId: null,
        lastReviewedAt: null,
        lastReviewedByUserId: null,
        createdAt: new Date('2026-04-21T00:00:00.000Z'),
        updatedAt: new Date('2026-04-21T00:00:00.000Z'),
      },
    },
  };

  return {
    ...base,
    ...overrides,
    sections: {
      ...base.sections,
      ...(overrides?.sections ?? {}),
    },
  };
}

function buildHandoff(overrides?: Partial<CpSettingsHandoffSnapshot>): CpSettingsHandoffSnapshot {
  const base: CpSettingsHandoffSnapshot = {
    contractVersion: 1,
    producedAt: new Date('2026-04-21T00:00:00.000Z'),
    mode: 'PRODUCER_ONLY',
    eligibility: 'READY_FOR_FUTURE_SETTINGS_CONSUMER',
    consumer: {
      settingsEnginePresent: true,
      cascadeStatus: 'SYNC_ACTIVE',
      blockingReasons: [],
    },
    account: {
      accountId: 'account-1',
      accountKey: 'tenant-1',
      accountName: 'Tenant 1',
      cpStatus: 'Active',
      cpRevision: 1,
    },
    provisioning: {
      isProvisioned: true,
      tenantId: 'tenant-1',
      tenantKey: 'tenant-1',
      tenantName: 'Tenant 1',
      tenantState: 'ACTIVE',
      publishedAt: new Date('2026-04-21T00:00:00.000Z'),
    },
    allowances: {
      access: {
        loginMethods: { password: true, google: false, microsoft: false },
        mfaPolicy: { adminRequired: true, memberRequired: false },
        signupPolicy: { publicSignup: false, adminInvitationsAllowed: true, allowedDomains: [] },
      },
      account: {
        branding: { logo: true, menuColor: true, fontColor: true, welcomeMessage: true },
        organizationStructure: { employers: true, locations: true },
        companyCalendar: { allowed: true },
      },
      modules: {
        modules: { personal: true, documents: false, benefits: false, payments: false },
      },
      personal: {
        families: [{ familyKey: 'identity', isAllowed: true }],
        fields: [
          {
            familyKey: 'identity',
            fieldKey: 'person.first_name',
            isAllowed: true,
            defaultSelected: true,
            minimumRequired: 'required',
            isSystemManaged: false,
          },
        ],
      },
      integrations: {
        integrations: [
          { integrationKey: 'integration.sso.google', isAllowed: false, capabilities: [] },
          { integrationKey: 'integration.sso.microsoft', isAllowed: false, capabilities: [] },
        ],
      },
    },
  };

  return {
    ...base,
    ...overrides,
    consumer: {
      ...base.consumer,
      ...(overrides?.consumer ?? {}),
    },
    account: {
      ...base.account,
      ...(overrides?.account ?? {}),
    },
    provisioning: {
      ...base.provisioning,
      ...(overrides?.provisioning ?? {}),
    },
    allowances: {
      ...base.allowances,
      ...(overrides?.allowances ?? {}),
    },
  };
}

describe('settings evaluators', () => {
  it('keeps aggregate COMPLETE when required sections are complete and personal is disabled', () => {
    const base = buildStateBundle();
    const state = buildStateBundle({
      sections: {
        access: { ...base.sections.access, status: 'COMPLETE' },
        account: { ...base.sections.account, status: 'NOT_STARTED' },
        personal: { ...base.sections.personal, status: 'NOT_STARTED' },
        integrations: { ...base.sections.integrations, status: 'NOT_STARTED' },
      },
    });

    expect(SetupAggregateEvaluator.evaluate({ state, personalRequired: false })).toBe('COMPLETE');
  });

  it('returns NEEDS_REVIEW when a required section is marked for review', () => {
    const base = buildStateBundle();
    const state = buildStateBundle({
      sections: {
        access: { ...base.sections.access, status: 'COMPLETE' },
        account: { ...base.sections.account, status: 'NOT_STARTED' },
        personal: { ...base.sections.personal, status: 'NEEDS_REVIEW' },
        integrations: { ...base.sections.integrations, status: 'NOT_STARTED' },
      },
    });

    expect(SetupAggregateEvaluator.evaluate({ state, personalRequired: true })).toBe(
      'NEEDS_REVIEW',
    );
  });

  it('returns BLOCKED integration state when login is enabled but readiness snapshot is unavailable', () => {
    const result = IntegrationStatusEvaluator.evaluate({
      integrationKey: 'integration.sso.google',
      isAllowed: true,
      loginMethodEnabled: true,
      readinessSnapshot: {
        providerKey: 'google',
        status: 'SNAPSHOT_UNAVAILABLE',
        asOf: new Date('2026-04-21T00:00:00.000Z'),
        detail: 'missing',
      },
    });

    expect(result.displayStatus).toBe('BLOCKED');
    expect(result.warnings).toHaveLength(1);
  });

  it('marks Personal for review when a required field is removed by CP', () => {
    const previous = buildHandoff();
    const next = buildHandoff({
      account: {
        accountId: 'account-1',
        accountKey: 'tenant-1',
        accountName: 'Tenant 1',
        cpStatus: 'Active',
        cpRevision: 2,
      },
      allowances: {
        ...previous.allowances,
        personal: {
          families: [{ familyKey: 'identity', isAllowed: true }],
          fields: [],
        },
      },
    });

    const result = NeedsReviewCascadeEvaluator.evaluate({ previous, next });
    expect(result.impactedSections).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          sectionKey: 'personal',
          reasonCode: 'CP_REQUIRED_TARGET_CHANGED',
        }),
      ]),
    );
  });
});
