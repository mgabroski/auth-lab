import { describe, it, expect } from 'vitest';
import { decideRegisterNextAction } from '../../../src/modules/auth/policies/register-next-action.policy';

describe('decideRegisterNextAction', () => {
  it('MEMBER with tenant flag off => NONE', () => {
    expect(
      decideRegisterNextAction({
        role: 'MEMBER',
        memberMfaRequired: false,
      }),
    ).toBe('NONE');
  });

  it('MEMBER with tenant flag on => MFA_SETUP_REQUIRED', () => {
    expect(
      decideRegisterNextAction({
        role: 'MEMBER',
        memberMfaRequired: true,
      }),
    ).toBe('MFA_SETUP_REQUIRED');
  });

  it('ADMIN always => MFA_SETUP_REQUIRED', () => {
    expect(
      decideRegisterNextAction({
        role: 'ADMIN',
        memberMfaRequired: false,
      }),
    ).toBe('MFA_SETUP_REQUIRED');
  });
});
