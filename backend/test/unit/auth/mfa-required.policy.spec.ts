import { describe, it, expect } from 'vitest';
import { isMfaRequiredForLogin } from '../../../src/modules/auth/policies/mfa-required.policy';

describe('isMfaRequiredForLogin', () => {
  it('requires MFA for ADMIN regardless of tenant setting', () => {
    expect(isMfaRequiredForLogin({ role: 'ADMIN', tenantMemberMfaRequired: false })).toBe(true);
    expect(isMfaRequiredForLogin({ role: 'ADMIN', tenantMemberMfaRequired: true })).toBe(true);
  });

  it('requires MFA for MEMBER only when tenant setting enforces it', () => {
    expect(isMfaRequiredForLogin({ role: 'MEMBER', tenantMemberMfaRequired: false })).toBe(false);
    expect(isMfaRequiredForLogin({ role: 'MEMBER', tenantMemberMfaRequired: true })).toBe(true);
  });
});
