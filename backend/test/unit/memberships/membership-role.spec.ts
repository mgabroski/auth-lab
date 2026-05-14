import { describe, expect, it } from 'vitest';

import {
  normalizeMembershipRole,
  parseMembershipRole,
  requireMembershipRole,
} from '../../../src/modules/memberships/membership-role';

describe('membership role normalization', () => {
  it('keeps canonical ADMIN / AGENT / USER roles unchanged', () => {
    expect(parseMembershipRole('ADMIN')).toBe('ADMIN');
    expect(parseMembershipRole('AGENT')).toBe('AGENT');
    expect(parseMembershipRole('USER')).toBe('USER');
  });

  it('maps legacy MEMBER to canonical USER', () => {
    expect(parseMembershipRole('MEMBER')).toBe('USER');
    expect(normalizeMembershipRole('MEMBER')).toBe('USER');
  });

  it('fails closed for invalid values', () => {
    expect(parseMembershipRole('OWNER')).toBeNull();
    expect(parseMembershipRole('')).toBeNull();
    expect(parseMembershipRole(null)).toBeNull();
    expect(parseMembershipRole(undefined)).toBeNull();
  });

  it('throws for invalid required role parsing', () => {
    expect(() => requireMembershipRole('OWNER')).toThrow('Invalid membership role.');
  });
});
