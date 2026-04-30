import { describe, expect, it } from 'vitest';

import { PersonalSettingsQueryService } from '../../../src/modules/settings/services/personal-settings-query.service';
import type { CpSettingsHandoffSnapshot } from '../../../src/modules/control-plane/accounts/handoff/cp-settings-handoff.types';
import type { TenantPersonalSettingsRecord } from '../../../src/modules/settings/dal/personal-settings.repo';

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
    consumer: { ...base.consumer, ...(overrides?.consumer ?? {}) },
    account: { ...base.account, ...(overrides?.account ?? {}) },
    provisioning: { ...base.provisioning, ...(overrides?.provisioning ?? {}) },
    allowances: { ...base.allowances, ...(overrides?.allowances ?? {}) },
  };
}

function emptySaved(): TenantPersonalSettingsRecord {
  return {
    families: [],
    fields: [],
    sections: [],
    sectionFields: [],
  };
}

describe('PersonalSettingsQueryService', () => {
  it('renders only CP-allowed families and fields and generates backend default sections', () => {
    const service = new PersonalSettingsQueryService();

    const result = service.build({
      sectionStatus: 'NOT_STARTED',
      cpHandoff: buildHandoff(),
      saved: emptySaved(),
    });

    expect(result.familyReview.families.map((family) => family.familyKey)).toEqual([
      'identity',
      'contact',
      'identifiers',
    ]);
    expect(
      result.fieldConfiguration.families.flatMap((family) =>
        family.fields.map((field) => field.fieldKey),
      ),
    ).toEqual(['person.first_name', 'person.middle_name', 'person.work_email', 'person.system_id']);
    expect(result.sectionBuilder.sections.map((section) => section.name)).toEqual([
      'Identity',
      'Contact',
      'Identifiers',
    ]);
  });

  it('locks required-floor and system-managed fields and treats unsaved defaults as in-progress', () => {
    const service = new PersonalSettingsQueryService();

    const result = service.build({
      sectionStatus: 'IN_PROGRESS',
      cpHandoff: buildHandoff(),
      saved: emptySaved(),
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
      includeRule: 'LOCKED_INCLUDED',
      requiredRule: 'LOCKED_REQUIRED',
      included: true,
      required: true,
    });
    expect(middleName).toMatchObject({
      includeRule: 'TENANT_CHOICE',
      requiredRule: 'TENANT_CHOICE',
    });
    expect(systemId).toMatchObject({
      includeRule: 'LOCKED_INCLUDED',
      requiredRule: 'SYSTEM_MANAGED',
      maskingRule: 'SYSTEM_MANAGED',
      included: true,
      required: true,
    });
  });

  it('surfaces saved family review and section assignment blockers honestly', () => {
    const service = new PersonalSettingsQueryService();

    const result = service.build({
      sectionStatus: 'NEEDS_REVIEW',
      cpHandoff: buildHandoff(),
      saved: {
        families: [
          {
            tenantId: 'tenant-1',
            familyKey: 'identity',
            reviewDecision: 'IN_USE',
            appliedCpRevision: 7,
            lastSavedAt: new Date('2026-04-22T00:00:00.000Z'),
            lastSavedByUserId: 'user-1',
            createdAt: new Date('2026-04-22T00:00:00.000Z'),
            updatedAt: new Date('2026-04-22T00:00:00.000Z'),
          },
        ],
        fields: [
          {
            tenantId: 'tenant-1',
            fieldKey: 'person.first_name',
            familyKey: 'identity',
            included: true,
            required: true,
            masked: false,
            appliedCpRevision: 7,
            lastSavedAt: new Date('2026-04-22T00:00:00.000Z'),
            lastSavedByUserId: 'user-1',
            createdAt: new Date('2026-04-22T00:00:00.000Z'),
            updatedAt: new Date('2026-04-22T00:00:00.000Z'),
          },
        ],
        sections: [
          {
            tenantId: 'tenant-1',
            sectionId: 'custom-1',
            sectionName: 'Custom',
            sortOrder: 0,
            appliedCpRevision: 7,
            lastSavedAt: new Date('2026-04-22T00:00:00.000Z'),
            lastSavedByUserId: 'user-1',
            createdAt: new Date('2026-04-22T00:00:00.000Z'),
            updatedAt: new Date('2026-04-22T00:00:00.000Z'),
          },
        ],
        sectionFields: [
          {
            tenantId: 'tenant-1',
            sectionId: 'custom-1',
            fieldKey: 'person.first_name',
            sortOrder: 0,
            createdAt: new Date('2026-04-22T00:00:00.000Z'),
          },
        ],
      },
    });

    expect(result.warnings).toContain(
      'Platform changes require your review before Personal can return to Complete.',
    );
    expect(result.progress.reviewedFamiliesCount).toBe(1);
    expect(result.progress.blockers).toContain('Required-floor fields still need configuration.');
    expect(result.conflictGuidance.summary).toContain('keep your local draft');
  });
});
