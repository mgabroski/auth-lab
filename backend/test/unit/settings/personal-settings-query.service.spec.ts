import { describe, expect, it } from 'vitest';

import { PersonalSettingsQueryService } from '../../../src/modules/settings/services/personal-settings-query.service';
import type { CpSettingsHandoffSnapshot } from '../../../src/modules/control-plane/accounts/handoff/cp-settings-handoff.types';

function buildHandoff(overrides?: Partial<CpSettingsHandoffSnapshot>): CpSettingsHandoffSnapshot {
  const base: CpSettingsHandoffSnapshot = {
    contractVersion: 1,
    producedAt: new Date('2026-04-22T00:00:00.000Z'),
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
      cpRevision: 7,
    },
    provisioning: {
      isProvisioned: true,
      tenantId: 'tenant-1',
      tenantKey: 'tenant-1',
      tenantName: 'Tenant 1',
      tenantState: 'ACTIVE',
      publishedAt: new Date('2026-04-22T00:00:00.000Z'),
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
        families: [
          { familyKey: 'identity', isAllowed: true },
          { familyKey: 'contact', isAllowed: true },
          { familyKey: 'identifiers', isAllowed: true },
          { familyKey: 'address', isAllowed: false },
        ],
        fields: [
          {
            familyKey: 'identity',
            fieldKey: 'person.first_name',
            isAllowed: true,
            defaultSelected: true,
            minimumRequired: 'required',
            isSystemManaged: false,
          },
          {
            familyKey: 'identity',
            fieldKey: 'person.middle_name',
            isAllowed: true,
            defaultSelected: false,
            minimumRequired: 'none',
            isSystemManaged: false,
          },
          {
            familyKey: 'contact',
            fieldKey: 'person.work_email',
            isAllowed: true,
            defaultSelected: true,
            minimumRequired: 'required',
            isSystemManaged: false,
          },
          {
            familyKey: 'identifiers',
            fieldKey: 'person.system_id',
            isAllowed: true,
            defaultSelected: false,
            minimumRequired: 'auto',
            isSystemManaged: true,
          },
          {
            familyKey: 'address',
            fieldKey: 'person.home_city',
            isAllowed: false,
            defaultSelected: false,
            minimumRequired: 'none',
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

describe('PersonalSettingsQueryService', () => {
  it('renders only CP-allowed families and hides non-allowed fields', () => {
    const service = new PersonalSettingsQueryService();

    const result = service.build({
      sectionStatus: 'NOT_STARTED',
      version: 3,
      cpRevision: 7,
      cpHandoff: buildHandoff(),
    });

    expect(result.moduleEnabled).toBe(true);
    expect(result.families.map((family) => family.familyKey)).toEqual([
      'identity',
      'contact',
      'identifiers',
    ]);
    expect(result.fieldConfiguration.families.map((family) => family.familyKey)).toEqual([
      'identity',
      'contact',
      'identifiers',
    ]);
    expect(
      result.fieldConfiguration.families.flatMap((family) =>
        family.fields.map((field) => field.fieldKey),
      ),
    ).toEqual(['person.first_name', 'person.middle_name', 'person.work_email', 'person.system_id']);
  });

  it('locks required-floor and system-managed fields in the field-configuration model', () => {
    const service = new PersonalSettingsQueryService();

    const result = service.build({
      sectionStatus: 'NOT_STARTED',
      version: 5,
      cpRevision: 9,
      cpHandoff: buildHandoff(),
    });

    const identityFamily = result.fieldConfiguration.families.find(
      (family) => family.familyKey === 'identity',
    );
    const firstName = identityFamily?.fields.find(
      (field) => field.fieldKey === 'person.first_name',
    );
    const middleName = identityFamily?.fields.find(
      (field) => field.fieldKey === 'person.middle_name',
    );
    const identifiersFamily = result.fieldConfiguration.families.find(
      (family) => family.familyKey === 'identifiers',
    );
    const systemId = identifiersFamily?.fields.find(
      (field) => field.fieldKey === 'person.system_id',
    );

    expect(identityFamily?.canExclude).toBe(false);
    expect(firstName).toMatchObject({
      readiness: 'CP_DEFAULT_SELECTED',
      requiredRule: 'LOCKED_REQUIRED',
      canBeExcludedLater: false,
      canToggleRequiredLater: false,
      canToggleMaskingLater: true,
    });
    expect(middleName).toMatchObject({
      readiness: 'AVAILABLE_TO_INCLUDE',
      requiredRule: 'TENANT_CHOICE',
      canBeExcludedLater: true,
      canToggleRequiredLater: true,
      canToggleMaskingLater: true,
    });
    expect(identifiersFamily?.canExclude).toBe(false);
    expect(systemId).toMatchObject({
      presentationState: 'READ_ONLY_SYSTEM_MANAGED',
      readiness: 'SYSTEM_MANAGED',
      requiredRule: 'SYSTEM_MANAGED',
      maskingRule: 'LOCKED_SYSTEM_MANAGED',
      canBeExcludedLater: false,
      canToggleRequiredLater: false,
      canToggleMaskingLater: false,
    });
  });

  it('carries review warnings and explicit conflict groundwork metadata', () => {
    const service = new PersonalSettingsQueryService();

    const result = service.build({
      sectionStatus: 'NEEDS_REVIEW',
      version: 11,
      cpRevision: 13,
      cpHandoff: buildHandoff(),
    });

    expect(result.warnings).toContain(
      'Platform changes require your review before Personal can return to Complete.',
    );
    expect(result.fieldConfiguration.conflictGuidance).toEqual({
      version: 11,
      cpRevision: 13,
      summary:
        'Use the current section version and CP revision as the future conflict baseline. Later Personal saves must preserve draft state on 409 and must not silently retry or discard.',
      notes: [
        'No Personal mutation route is shipped in this phase, so there is no fake save success path.',
        'If CP changes before the later save contract ships, the next read reflects the latest allowed universe immediately.',
      ],
    });
  });
});
