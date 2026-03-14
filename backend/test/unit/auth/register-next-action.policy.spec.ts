import { describe, expect, it } from 'vitest';

import { decideRegisterNextAction } from '../../../src/modules/auth/policies/register-next-action.policy';

type Scenario = {
  name: string;
  input: {
    role: 'ADMIN' | 'MEMBER';
    memberMfaRequired: boolean;
    emailVerified?: boolean;
  };
  expected: 'NONE' | 'MFA_SETUP_REQUIRED' | 'EMAIL_VERIFICATION_REQUIRED';
};

const SCENARIOS: Scenario[] = [
  {
    name: 'member with no MFA requirement resolves to NONE',
    input: {
      role: 'MEMBER',
      memberMfaRequired: false,
    },
    expected: 'NONE',
  },
  {
    name: 'member with tenant MFA requirement resolves to MFA_SETUP_REQUIRED',
    input: {
      role: 'MEMBER',
      memberMfaRequired: true,
    },
    expected: 'MFA_SETUP_REQUIRED',
  },
  {
    name: 'admin invite registration resolves to MFA_SETUP_REQUIRED',
    input: {
      role: 'ADMIN',
      memberMfaRequired: false,
    },
    expected: 'MFA_SETUP_REQUIRED',
  },
  {
    name: 'email verification takes precedence over registration MFA outcomes',
    input: {
      role: 'ADMIN',
      memberMfaRequired: true,
      emailVerified: false,
    },
    expected: 'EMAIL_VERIFICATION_REQUIRED',
  },
];

describe('decideRegisterNextAction', () => {
  for (const scenario of SCENARIOS) {
    it(scenario.name, () => {
      expect(decideRegisterNextAction(scenario.input)).toBe(scenario.expected);
    });
  }
});
