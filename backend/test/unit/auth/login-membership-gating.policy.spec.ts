import { describe, it, expect } from 'vitest';
import {
  assertLoginMembershipAllowed,
  getLoginMembershipGatingFailure,
} from '../../../src/modules/auth/policies/login-membership-gating.policy';

describe('getLoginMembershipGatingFailure', () => {
  it('assertLoginMembershipAllowed does not throw for ACTIVE', () => {
    expect(() =>
      assertLoginMembershipAllowed({ id: 'm1', role: 'ADMIN', status: 'ACTIVE' }),
    ).not.toThrow();
  });

  it('returns failure for missing membership', () => {
    const res = getLoginMembershipGatingFailure(undefined);
    expect(res).not.toBeNull();
    expect(res!.reason).toBe('no_membership');
  });

  it('returns failure for SUSPENDED membership', () => {
    const res = getLoginMembershipGatingFailure({ id: 'm1', role: 'MEMBER', status: 'SUSPENDED' });
    expect(res).not.toBeNull();
    expect(res!.reason).toBe('suspended');
  });

  it('returns failure for INVITED membership', () => {
    const res = getLoginMembershipGatingFailure({ id: 'm1', role: 'MEMBER', status: 'INVITED' });
    expect(res).not.toBeNull();
    expect(res!.reason).toBe('invite_not_accepted');
  });

  it('returns null for ACTIVE membership', () => {
    const res = getLoginMembershipGatingFailure({ id: 'm1', role: 'ADMIN', status: 'ACTIVE' });
    expect(res).toBeNull();
  });
});
