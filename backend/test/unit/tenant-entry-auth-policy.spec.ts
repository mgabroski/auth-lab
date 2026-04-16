import { describe, it, expect } from 'vitest';

import {
  decideTenantEntryAuthPolicy,
  isNextActionAllowedForDecision,
} from '../../src/modules/_shared/policies/tenant-entry-auth-policy';
import { buildTenantEntryPolicyInput } from '../../src/modules/_shared/policies/tenant-entry-policy-input';
import type { Invite } from '../../src/modules/invites/invite.types';
import type { Membership } from '../../src/modules/memberships/membership.types';
import type { Tenant } from '../../src/modules/tenants/tenant.types';

function makeTenant(overrides: Partial<Tenant> = {}): Tenant {
  return {
    id: 'tenant-1',
    key: 'acme',
    name: 'Acme',
    isActive: true,
    publicSignupEnabled: false,
    adminInviteRequired: false,
    memberMfaRequired: false,
    allowedEmailDomains: ['acme.com'],
    allowedSso: ['google'],
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    updatedAt: new Date('2026-01-01T00:00:00.000Z'),
    ...overrides,
    setupCompletedAt: overrides.setupCompletedAt ?? null,
  };
}

function makeInvite(overrides: Partial<Invite> = {}): Invite {
  return {
    id: 'invite-1',
    tenantId: 'tenant-1',
    email: 'user@acme.com',
    role: 'MEMBER',
    status: 'PENDING',
    tokenHash: 'hashed-token',
    expiresAt: new Date('2026-01-10T00:00:00.000Z'),
    usedAt: null,
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    createdByUserId: 'admin-1',
    ...overrides,
  };
}

function makeMembership(overrides: Partial<Membership> = {}): Membership {
  return {
    id: 'membership-1',
    tenantId: 'tenant-1',
    userId: 'user-1',
    role: 'MEMBER',
    status: 'INVITED',
    invitedAt: new Date('2026-01-01T00:00:00.000Z'),
    acceptedAt: null,
    suspendedAt: null,
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    updatedAt: new Date('2026-01-01T00:00:00.000Z'),
    ...overrides,
  };
}

describe('decideTenantEntryAuthPolicy', () => {
  it('classifies public-signup-allowed entry and only allows the public-signup nextAction family', () => {
    const input = buildTenantEntryPolicyInput({
      tenant: makeTenant({ publicSignupEnabled: true, adminInviteRequired: false }),
      now: new Date('2026-01-05T00:00:00.000Z'),
    });

    const decision = decideTenantEntryAuthPolicy(input);

    expect(decision.code).toBe('PUBLIC_SIGNUP_ALLOWED');
    expect(decision.entryPath).toBe('PUBLIC_SIGNUP');
    expect(decision.isEntryAllowed).toBe(true);
    expect(decision.allowedNextActions).toEqual(['NONE', 'EMAIL_VERIFICATION_REQUIRED']);
    expect(decision.forbiddenNextActions).toEqual(['MFA_SETUP_REQUIRED', 'MFA_REQUIRED']);
    expect(isNextActionAllowedForDecision(decision, 'EMAIL_VERIFICATION_REQUIRED')).toBe(true);
    expect(isNextActionAllowedForDecision(decision, 'MFA_REQUIRED')).toBe(false);
  });

  it('classifies public-signup-blocked entry when signup is off and no invite path exists', () => {
    const input = buildTenantEntryPolicyInput({
      tenant: makeTenant({ publicSignupEnabled: false, adminInviteRequired: false }),
      now: new Date('2026-01-05T00:00:00.000Z'),
    });

    const decision = decideTenantEntryAuthPolicy(input);

    expect(decision.code).toBe('PUBLIC_SIGNUP_BLOCKED');
    expect(decision.entryPath).toBe('BLOCKED');
    expect(decision.isEntryAllowed).toBe(false);
    expect(decision.allowedNextActions).toEqual([]);
    expect(decision.forbiddenNextActions).toEqual([
      'NONE',
      'EMAIL_VERIFICATION_REQUIRED',
      'MFA_SETUP_REQUIRED',
      'MFA_REQUIRED',
    ]);
  });

  it('classifies invite-required entry distinctly from generic public-signup-blocked entry', () => {
    const input = buildTenantEntryPolicyInput({
      tenant: makeTenant({ publicSignupEnabled: true, adminInviteRequired: true }),
      now: new Date('2026-01-05T00:00:00.000Z'),
    });

    const decision = decideTenantEntryAuthPolicy(input);

    expect(decision.code).toBe('INVITE_REQUIRED');
    expect(decision.entryPath).toBe('BLOCKED');
    expect(decision.isEntryAllowed).toBe(false);
    expect(decision.allowedNextActions).toEqual([]);
  });

  it('classifies valid invited entry and forbids EMAIL_VERIFICATION_REQUIRED for that path', () => {
    const input = buildTenantEntryPolicyInput({
      tenant: makeTenant({ publicSignupEnabled: false, adminInviteRequired: true }),
      invite: makeInvite({ status: 'PENDING' }),
      now: new Date('2026-01-05T00:00:00.000Z'),
    });

    const decision = decideTenantEntryAuthPolicy(input);

    expect(decision.code).toBe('INVITED_VALID');
    expect(decision.entryPath).toBe('INVITED_ENTRY');
    expect(decision.isEntryAllowed).toBe(true);
    expect(decision.allowedNextActions).toEqual(['NONE', 'MFA_SETUP_REQUIRED', 'MFA_REQUIRED']);
    expect(decision.forbiddenNextActions).toEqual(['EMAIL_VERIFICATION_REQUIRED']);
    expect(isNextActionAllowedForDecision(decision, 'MFA_SETUP_REQUIRED')).toBe(true);
    expect(isNextActionAllowedForDecision(decision, 'EMAIL_VERIFICATION_REQUIRED')).toBe(false);
  });

  it('classifies expired invited entry distinctly as blocked once expired-invite SSO activation is closed', () => {
    const input = buildTenantEntryPolicyInput({
      tenant: makeTenant({ publicSignupEnabled: false, adminInviteRequired: true }),
      invite: makeInvite({ status: 'PENDING', expiresAt: new Date('2026-01-02T00:00:00.000Z') }),
      now: new Date('2026-01-05T00:00:00.000Z'),
    });

    const decision = decideTenantEntryAuthPolicy(input);

    expect(decision.code).toBe('INVITED_EXPIRED');
    expect(decision.entryPath).toBe('BLOCKED');
    expect(decision.isEntryAllowed).toBe(false);
    expect(decision.allowedNextActions).toEqual([]);
  });

  it('classifies existing ACTIVE membership as existing-member auth and allows the full login nextAction family', () => {
    const input = buildTenantEntryPolicyInput({
      tenant: makeTenant({ publicSignupEnabled: false, adminInviteRequired: true }),
      membership: makeMembership({
        status: 'ACTIVE',
        acceptedAt: new Date('2026-01-03T00:00:00.000Z'),
      }),
      now: new Date('2026-01-05T00:00:00.000Z'),
    });

    const decision = decideTenantEntryAuthPolicy(input);

    expect(decision.code).toBe('ACTIVE_MEMBERSHIP');
    expect(decision.entryPath).toBe('EXISTING_MEMBER_AUTH');
    expect(decision.isEntryAllowed).toBe(true);
    expect(decision.allowedNextActions).toEqual([
      'NONE',
      'EMAIL_VERIFICATION_REQUIRED',
      'MFA_SETUP_REQUIRED',
      'MFA_REQUIRED',
    ]);
  });

  it('classifies existing SUSPENDED membership as blocked regardless of tenant public-signup settings', () => {
    const input = buildTenantEntryPolicyInput({
      tenant: makeTenant({ publicSignupEnabled: true, adminInviteRequired: false }),
      membership: makeMembership({
        status: 'SUSPENDED',
        suspendedAt: new Date('2026-01-03T00:00:00.000Z'),
      }),
      now: new Date('2026-01-05T00:00:00.000Z'),
    });

    const decision = decideTenantEntryAuthPolicy(input);

    expect(decision.code).toBe('SUSPENDED_MEMBERSHIP');
    expect(decision.entryPath).toBe('BLOCKED');
    expect(decision.isEntryAllowed).toBe(false);
    expect(decision.allowedNextActions).toEqual([]);
  });

  it('keeps pending activation after one-time invite consumption explicit as invited-entry state', () => {
    const input = buildTenantEntryPolicyInput({
      tenant: makeTenant({ publicSignupEnabled: false, adminInviteRequired: true }),
      invite: makeInvite({
        status: 'ACCEPTED',
        usedAt: new Date('2026-01-03T00:00:00.000Z'),
      }),
      now: new Date('2026-01-05T00:00:00.000Z'),
    });

    const decision = decideTenantEntryAuthPolicy(input);

    expect(decision.code).toBe('INVITED_PENDING_ACTIVATION');
    expect(decision.entryPath).toBe('INVITED_ENTRY');
    expect(decision.isEntryAllowed).toBe(true);
    expect(decision.allowedNextActions).toEqual(['NONE', 'MFA_SETUP_REQUIRED', 'MFA_REQUIRED']);
  });
});
