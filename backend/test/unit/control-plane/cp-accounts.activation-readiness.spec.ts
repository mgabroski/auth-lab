import { describe, expect, it } from 'vitest';

import { evaluateCpActivationReadiness } from '../../../src/modules/control-plane/accounts/cp-accounts.domain';
import type { CpAccountDetail } from '../../../src/modules/control-plane/accounts/cp-accounts.types';

function makeBaseAccount(): CpAccountDetail {
  return {
    id: 'cp-account-1',
    accountName: 'QA Tenant',
    accountKey: 'qa-tenant',
    cpStatus: 'Draft',
    cpRevision: 0,
    createdAt: new Date('2026-04-17T00:00:00.000Z'),
    updatedAt: new Date('2026-04-17T00:00:00.000Z'),
    step2Progress: {
      configuredCount: 3,
      totalCount: 4,
      requiredConfiguredCount: 3,
      requiredTotalCount: 3,
      canContinueToReview: true,
      groups: [],
    },
    access: {
      configured: true,
      loginMethods: {
        password: true,
        google: false,
        microsoft: false,
      },
      mfaPolicy: {
        adminRequired: true,
        memberRequired: false,
      },
      signupPolicy: {
        publicSignup: false,
        adminInvitationsAllowed: true,
        allowedDomains: [],
      },
    },
    accountSettings: {
      configured: true,
      branding: {
        logo: true,
        menuColor: true,
        fontColor: true,
        welcomeMessage: true,
      },
      organizationStructure: {
        employers: true,
        locations: true,
      },
      companyCalendar: {
        allowed: true,
      },
    },
    moduleSettings: {
      configured: true,
      moduleDecisionsSaved: true,
      personalSubpageSaved: false,
      modules: {
        personal: false,
        documents: false,
        benefits: false,
        payments: false,
      },
    },
    personal: {
      saved: false,
      families: [],
    },
    integrations: {
      configured: true,
      integrations: [
        {
          integrationKey: 'integration.sso.google',
          label: 'Google SSO Integration',
          isAllowed: false,
          capabilities: [],
        },
        {
          integrationKey: 'integration.sso.microsoft',
          label: 'Microsoft SSO Integration',
          isAllowed: false,
          capabilities: [],
        },
      ],
    },
    settingsHandoff: {
      contractVersion: 1,
      producedAt: new Date('2026-04-17T00:00:00.000Z'),
      mode: 'PRODUCER_ONLY',
      eligibility: 'BLOCKED_UNPUBLISHED_ACCOUNT',
      consumer: {
        settingsEnginePresent: true,
        cascadeStatus: 'SYNC_ACTIVE',
        blockingReasons: [],
      },
      account: {
        accountId: 'cp-account-1',
        accountKey: 'qa-tenant',
        accountName: 'QA Tenant',
        cpStatus: 'Draft',
        cpRevision: 0,
      },
      provisioning: {
        isProvisioned: false,
        tenantId: null,
        tenantKey: null,
        tenantName: null,
        tenantState: 'NOT_PROVISIONED',
        publishedAt: null,
      },
      allowances: {
        access: {
          loginMethods: {
            password: true,
            google: false,
            microsoft: false,
          },
          mfaPolicy: {
            adminRequired: true,
            memberRequired: false,
          },
          signupPolicy: {
            publicSignup: false,
            adminInvitationsAllowed: true,
            allowedDomains: [],
          },
        },
        account: {
          branding: {
            logo: true,
            menuColor: true,
            fontColor: true,
            welcomeMessage: true,
          },
          organizationStructure: {
            employers: true,
            locations: true,
          },
          companyCalendar: {
            allowed: true,
          },
        },
        modules: {
          modules: {
            personal: false,
            documents: false,
            benefits: false,
            payments: false,
          },
        },
        personal: {
          families: [],
          fields: [],
        },
        integrations: {
          integrations: [],
        },
      },
    },
  };
}

describe('evaluateCpActivationReadiness', () => {
  it('passes the minimal ready path when required decisions are saved and Personal is not enabled', () => {
    const readiness = evaluateCpActivationReadiness(makeBaseAccount());

    expect(readiness.isReady).toBe(true);
    expect(readiness.blockingReasons).toEqual([]);
  });

  it('blocks publish when no login method is enabled', () => {
    const account = makeBaseAccount();
    account.access.loginMethods = {
      password: false,
      google: false,
      microsoft: false,
    };

    const readiness = evaluateCpActivationReadiness(account);

    expect(readiness.isReady).toBe(false);
    expect(readiness.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'LOGIN_METHOD_SELECTED',
          passed: false,
        }),
      ]),
    );
    expect(readiness.blockingReasons).toContain(
      'Select at least one login method before publishing Active.',
    );
  });

  it('blocks publish when Personal is enabled but the Personal sub-page has not been saved', () => {
    const account = makeBaseAccount();
    account.moduleSettings = {
      configured: false,
      moduleDecisionsSaved: true,
      personalSubpageSaved: false,
      modules: {
        personal: true,
        documents: false,
        benefits: false,
        payments: false,
      },
    };
    account.personal = {
      saved: false,
      families: [],
    };

    const readiness = evaluateCpActivationReadiness(account);

    expect(readiness.isReady).toBe(false);
    expect(readiness.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'PERSONAL_CATALOG_DEFINED',
          passed: false,
          detail: 'Save the Personal CP sub-page because Personal is enabled.',
        }),
      ]),
    );
  });

  it('blocks publish when an enabled SSO login method lacks the required integration allowance', () => {
    const account = makeBaseAccount();
    account.access.loginMethods = {
      password: true,
      google: true,
      microsoft: false,
    };

    const readiness = evaluateCpActivationReadiness(account);

    expect(readiness.isReady).toBe(false);
    expect(readiness.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'INTEGRATION_DECISIONS_RELEVANT',
          passed: false,
          detail: 'Google login is enabled but Google SSO Integration is not allowed.',
        }),
      ]),
    );
  });
});
