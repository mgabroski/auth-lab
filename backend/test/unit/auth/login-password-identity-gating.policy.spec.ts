import { describe, it, expect } from 'vitest';
import { getLoginPasswordIdentityFailure } from '../../../src/modules/auth/policies/login-password-identity-gating.policy';

describe('getLoginPasswordIdentityFailure', () => {
  it('fails when password identity is undefined', () => {
    const res = getLoginPasswordIdentityFailure(undefined);
    expect(res).not.toBeNull();
    expect(res!.reason).toBe('no_password_identity');
  });

  it('fails when password identity is null', () => {
    const res = getLoginPasswordIdentityFailure(null);
    expect(res).not.toBeNull();
    expect(res!.reason).toBe('no_password_identity');
  });

  it('passes when identity exists', () => {
    const res = getLoginPasswordIdentityFailure({ passwordHash: 'hash' });
    expect(res).toBeNull();
  });
});
