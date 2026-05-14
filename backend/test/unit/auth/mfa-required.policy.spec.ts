import { describe, it, expect } from 'vitest';
import { isMfaRequiredForLogin } from '../../../src/modules/auth/policies/mfa-required.policy';

describe('isMfaRequiredForLogin', () => {
  it('requires MFA for ADMIN regardless of tenant setting', () => {
    expect(isMfaRequiredForLogin({ role: 'ADMIN', tenantMemberMfaRequired: false })).toBe(true);
    expect(isMfaRequiredForLogin({ role: 'ADMIN', tenantMemberMfaRequired: true })).toBe(true);
  });

  it('requires MFA for AGENT only when tenant non-admin policy enforces it', () => {
    expect(isMfaRequiredForLogin({ role: 'AGENT', tenantMemberMfaRequired: false })).toBe(false);
    expect(isMfaRequiredForLogin({ role: 'AGENT', tenantMemberMfaRequired: true })).toBe(true);
  });

  it('requires MFA for USER only when tenant non-admin policy enforces it', () => {
    expect(isMfaRequiredForLogin({ role: 'USER', tenantMemberMfaRequired: false })).toBe(false);
    expect(isMfaRequiredForLogin({ role: 'USER', tenantMemberMfaRequired: true })).toBe(true);
  });
});
