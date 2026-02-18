import { describe, it, expect } from 'vitest';
import { decideLoginNextAction } from '../../../src/modules/auth/policies/login-next-action.policy';

describe('decideLoginNextAction', () => {
  it('MEMBER with tenant flag off => NONE', () => {
    expect(
      decideLoginNextAction({
        role: 'MEMBER',
        memberMfaRequired: false,
        hasVerifiedMfaSecret: false,
      }),
    ).toBe('NONE');
  });

  it('MEMBER with tenant flag on + no verified secret => MFA_SETUP_REQUIRED', () => {
    expect(
      decideLoginNextAction({
        role: 'MEMBER',
        memberMfaRequired: true,
        hasVerifiedMfaSecret: false,
      }),
    ).toBe('MFA_SETUP_REQUIRED');
  });

  it('MEMBER with tenant flag on + verified secret => MFA_REQUIRED', () => {
    expect(
      decideLoginNextAction({
        role: 'MEMBER',
        memberMfaRequired: true,
        hasVerifiedMfaSecret: true,
      }),
    ).toBe('MFA_REQUIRED');
  });

  it('ADMIN always requires MFA: no verified secret => MFA_SETUP_REQUIRED', () => {
    expect(
      decideLoginNextAction({
        role: 'ADMIN',
        memberMfaRequired: false,
        hasVerifiedMfaSecret: false,
      }),
    ).toBe('MFA_SETUP_REQUIRED');
  });

  it('ADMIN always requires MFA: verified secret => MFA_REQUIRED', () => {
    expect(
      decideLoginNextAction({
        role: 'ADMIN',
        memberMfaRequired: false,
        hasVerifiedMfaSecret: true,
      }),
    ).toBe('MFA_REQUIRED');
  });
});
