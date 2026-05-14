import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { PeopleTeamsView } from '../../../../src/shared/people-teams/components/people-teams-view';
import type { PeopleTeamsFoundationResponse } from '../../../../src/shared/people-teams/contracts';

function makeData(
  overrides: Partial<PeopleTeamsFoundationResponse> = {},
): PeopleTeamsFoundationResponse {
  return {
    groups: [
      {
        id: 'group-1',
        name: 'HR Agents',
        normalizedName: 'hr agents',
        description: 'Human resources group',
        level: 'AGENT',
        status: 'ACTIVE',
        memberCount: 0,
        createdAt: '2026-05-14T00:00:00.000Z',
        updatedAt: '2026-05-14T00:00:00.000Z',
        archivedAt: null,
      },
    ],
    people: [
      {
        membershipId: 'membership-1',
        userId: 'user-1',
        email: 'admin@example.com',
        name: 'Admin User',
        role: 'ADMIN',
        status: 'ACTIVE',
      },
    ],
    ...overrides,
  };
}

describe('PeopleTeamsView', () => {
  it('renders group foundation copy without Operational Access UI', () => {
    const html = renderToStaticMarkup(
      React.createElement(PeopleTeamsView, { initialData: makeData() }),
    );

    expect(html).toContain('Groups');
    expect(html).toContain('HR Agents');
    expect(html).toContain('Group level is classification only for now');
    expect(html).toContain('does not change a user&#x27;s login role');
    expect(html).toContain('does not grant module access');
    expect(html).toContain('Operational Access will be configured later');
    expect(html).not.toContain('Can see');
    expect(html).not.toContain('Can do');
    expect(html).not.toContain('Person Exceptions');
    expect(html).not.toContain('Managed People');
    expect(html).not.toContain('Where');
    expect(html).not.toContain('Access grants');
  });

  it('renders empty group and member states', () => {
    const html = renderToStaticMarkup(
      React.createElement(PeopleTeamsView, { initialData: makeData({ groups: [], people: [] }) }),
    );

    expect(html).toContain('No groups yet');
    expect(html).toContain('Create your first reusable People &amp; Teams group');
    expect(html).toContain('Create or select a group before managing members');
  });
});
