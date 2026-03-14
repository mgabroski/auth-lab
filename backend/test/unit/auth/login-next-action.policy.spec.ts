import { describe, expect, it } from 'vitest';

import { decideLoginNextAction } from '../../../src/modules/auth/policies/login-next-action.policy';

type Scenario = {
  name: string;
  input: {
    role: 'ADMIN' | 'MEMBER';
    memberMfaRequired: boolean;
    hasVerifiedMfaSecret: boolean;
    emailVerified?: boolean;
  };
  expected: 'NONE' | 'MFA_SETUP_REQUIRED' | 'MFA_REQUIRED' | 'EMAIL_VERIFICATION_REQUIRED';
};

const SCENARIOS: Scenario[] = [
  {
    name: 'member with no MFA requirement resolves to NONE',
    input: {
      role: 'MEMBER',
      memberMfaRequired: false,
      hasVerifiedMfaSecret: false,
    },
    expected: 'NONE',
  },
  {
    name: 'member with tenant MFA requirement and no verified secret resolves to MFA_SETUP_REQUIRED',
    input: {
      role: 'MEMBER',
      memberMfaRequired: true,
      hasVerifiedMfaSecret: false,
    },
    expected: 'MFA_SETUP_REQUIRED',
  },
  {
    name: 'member with tenant MFA requirement and verified secret resolves to MFA_REQUIRED',
    input: {
      role: 'MEMBER',
      memberMfaRequired: true,
      hasVerifiedMfaSecret: true,
    },
    expected: 'MFA_REQUIRED',
  },
  {
    name: 'admin without verified MFA resolves to MFA_SETUP_REQUIRED regardless of tenant member flag',
    input: {
      role: 'ADMIN',
      memberMfaRequired: false,
      hasVerifiedMfaSecret: false,
    },
    expected: 'MFA_SETUP_REQUIRED',
  },
  {
    name: 'admin with verified MFA resolves to MFA_REQUIRED regardless of tenant member flag',
    input: {
      role: 'ADMIN',
      memberMfaRequired: false,
      hasVerifiedMfaSecret: true,
    },
    expected: 'MFA_REQUIRED',
  },
  {
    name: 'email verification takes precedence over all MFA outcomes',
    input: {
      role: 'ADMIN',
      memberMfaRequired: true,
      hasVerifiedMfaSecret: true,
      emailVerified: false,
    },
    expected: 'EMAIL_VERIFICATION_REQUIRED',
  },
];

describe('decideLoginNextAction', () => {
  for (const scenario of SCENARIOS) {
    it(scenario.name, () => {
      expect(decideLoginNextAction(scenario.input)).toBe(scenario.expected);
    });
  }
});
