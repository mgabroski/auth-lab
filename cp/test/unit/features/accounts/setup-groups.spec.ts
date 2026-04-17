import { describe, expect, it } from 'vitest';

import {
  getSetupGroupBySlug,
  isSetupGroupSlug,
  SETUP_GROUPS,
  TOTAL_SETUP_GROUPS,
} from '@/features/accounts/setup-groups';

describe('CP setup groups', () => {
  it('keeps the locked Step 2 four-group structure and ordering', () => {
    expect(TOTAL_SETUP_GROUPS).toBe(4);
    expect(
      SETUP_GROUPS.map((group) => ({
        slug: group.slug,
        isRequired: group.isRequired,
        title: group.title,
      })),
    ).toEqual([
      {
        slug: 'access-identity-security',
        isRequired: true,
        title: 'Access, Identity & Security',
      },
      {
        slug: 'account-settings',
        isRequired: true,
        title: 'Account Settings',
      },
      {
        slug: 'module-settings',
        isRequired: true,
        title: 'Module Settings',
      },
      {
        slug: 'integrations-marketplace',
        isRequired: false,
        title: 'Integrations & Marketplace',
      },
    ]);
  });

  it('recognizes only valid setup-group slugs', () => {
    expect(isSetupGroupSlug('module-settings')).toBe(true);
    expect(getSetupGroupBySlug('module-settings')?.title).toBe('Module Settings');

    expect(isSetupGroupSlug('communications')).toBe(false);
    expect(getSetupGroupBySlug('communications')).toBeNull();
  });
});
