import { describe, it, expect } from 'vitest';

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
    adminInviteRequired: true,
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

describe('buildTenantEntryPolicyInput', () => {
  it('represents a valid pending invite as INVITED + VALID without activation yet', () => {
    const result = buildTenantEntryPolicyInput({
      tenant: makeTenant(),
      invite: makeInvite({ status: 'PENDING' }),
      now: new Date('2026-01-05T00:00:00.000Z'),
    });

    expect(result.tenant.adminInviteRequired).toBe(true);
    expect(result.invite.state).toBe('VALID');
    expect(result.entry.state).toBe('INVITED');
    expect(result.entry.activationState).toBe('NONE');
    expect(result.entry.canActivateLater).toBe(false);
  });

  it('represents an expired pending invite without silently converting it to another policy', () => {
    const result = buildTenantEntryPolicyInput({
      tenant: makeTenant(),
      invite: makeInvite({ status: 'PENDING', expiresAt: new Date('2026-01-02T00:00:00.000Z') }),
      now: new Date('2026-01-05T00:00:00.000Z'),
    });

    expect(result.invite.rawStatus).toBe('PENDING');
    expect(result.invite.state).toBe('EXPIRED');
    expect(result.entry.state).toBe('INVITED');
    expect(result.entry.activationState).toBe('NONE');
  });

  it('represents a one-time used invite as pending later activation when membership is not active yet', () => {
    const result = buildTenantEntryPolicyInput({
      tenant: makeTenant(),
      invite: makeInvite({
        status: 'ACCEPTED',
        usedAt: new Date('2026-01-03T00:00:00.000Z'),
      }),
      now: new Date('2026-01-05T00:00:00.000Z'),
    });

    expect(result.invite.state).toBe('ONE_TIME_USED');
    expect(result.entry.state).toBe('INVITED');
    expect(result.entry.activationState).toBe('PENDING');
    expect(result.entry.canActivateLater).toBe(true);
  });

  it('represents active membership as ACTIVE even when invite token was already consumed', () => {
    const result = buildTenantEntryPolicyInput({
      tenant: makeTenant(),
      invite: makeInvite({
        status: 'ACCEPTED',
        usedAt: new Date('2026-01-03T00:00:00.000Z'),
      }),
      membership: makeMembership({
        status: 'ACTIVE',
        acceptedAt: new Date('2026-01-04T00:00:00.000Z'),
      }),
      now: new Date('2026-01-05T00:00:00.000Z'),
    });

    expect(result.membership.state).toBe('ACTIVE');
    expect(result.invite.state).toBe('ONE_TIME_USED');
    expect(result.entry.state).toBe('ACTIVE');
    expect(result.entry.activationState).toBe('ACTIVE');
    expect(result.entry.canActivateLater).toBe(false);
  });

  it('supports a future INVITED membership row even when no invite row is present', () => {
    const result = buildTenantEntryPolicyInput({
      tenant: makeTenant(),
      membership: makeMembership({ status: 'INVITED' }),
      now: new Date('2026-01-05T00:00:00.000Z'),
    });

    expect(result.invite.state).toBe('NONE');
    expect(result.membership.state).toBe('INVITED');
    expect(result.entry.state).toBe('INVITED');
    expect(result.entry.activationState).toBe('PENDING');
    expect(result.entry.canActivateLater).toBe(true);
  });
});
