import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

vi.mock('next/link', () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) =>
    React.createElement('a', { href }, children),
}));

import {
  AdminInviteAgentGroupSelector,
  AdminInviteManagement,
  INVITE_LEVEL_OPTIONS,
  buildCreateInviteRequest,
  getInviteLevelLabel,
  getSelectedAgentGroupIdsForLevel,
  getSelectableAgentGroups,
  shouldShowAgentGroupSelector,
  validateInviteDraft,
} from '../../../../src/shared/auth/components/admin-invite-management';
import type { PeopleTeamGroup } from '../../../../src/shared/people-teams/contracts';

function makeGroup(overrides: Partial<PeopleTeamGroup> = {}): PeopleTeamGroup {
  return {
    id: 'group-1',
    name: 'HR Agents',
    normalizedName: 'hr agents',
    description: null,
    level: 'AGENT',
    status: 'ACTIVE',
    memberCount: 0,
    createdAt: '2026-05-14T00:00:00.000Z',
    updatedAt: '2026-05-14T00:00:00.000Z',
    archivedAt: null,
    ...overrides,
  };
}

describe('AdminInviteManagement helpers', () => {
  it('exposes User / Agent / Admin levels without MEMBER as a selectable option', () => {
    expect(INVITE_LEVEL_OPTIONS).toEqual([
      { value: 'USER', label: 'User' },
      { value: 'AGENT', label: 'Agent' },
      { value: 'ADMIN', label: 'Admin' },
    ]);
    expect(INVITE_LEVEL_OPTIONS.some((option) => String(option.value) === 'MEMBER')).toBe(false);
    expect(getInviteLevelLabel('MEMBER')).toBe('User');
  });

  it('shows the Agent group selector only for Agent level', () => {
    expect(shouldShowAgentGroupSelector('AGENT')).toBe(true);
    expect(shouldShowAgentGroupSelector('USER')).toBe(false);
    expect(shouldShowAgentGroupSelector('ADMIN')).toBe(false);
  });

  it('clears selected Agent groups when Level changes away from Agent', () => {
    expect(getSelectedAgentGroupIdsForLevel('AGENT', ['group-1'])).toEqual(['group-1']);
    expect(getSelectedAgentGroupIdsForLevel('USER', ['group-1'])).toEqual([]);
    expect(getSelectedAgentGroupIdsForLevel('ADMIN', ['group-1'])).toEqual([]);
  });

  it('validates Agent group requirements and builds exact backend payloads', () => {
    expect(
      validateInviteDraft({
        email: 'agent@example.com',
        level: 'AGENT',
        selectedAgentGroupIds: [],
      }),
    ).toBe('Select at least one active Agent group before inviting an Agent.');
    expect(
      validateInviteDraft({
        email: 'agent@example.com',
        level: 'AGENT',
        selectedAgentGroupIds: ['group-1'],
      }),
    ).toBeNull();

    expect(
      buildCreateInviteRequest({
        email: 'agent@example.com',
        level: 'AGENT',
        selectedAgentGroupIds: ['group-1'],
      }),
    ).toEqual({ email: 'agent@example.com', role: 'AGENT', agentGroupIds: ['group-1'] });
    expect(
      buildCreateInviteRequest({
        email: 'user@example.com',
        level: 'USER',
        selectedAgentGroupIds: ['stale-group'],
      }),
    ).toEqual({ email: 'user@example.com', role: 'USER' });
    expect(
      buildCreateInviteRequest({
        email: 'admin@example.com',
        level: 'ADMIN',
        selectedAgentGroupIds: ['stale-group'],
      }),
    ).toEqual({ email: 'admin@example.com', role: 'ADMIN' });
  });

  it('filters selectable groups to active Agent groups only', () => {
    const selectable = getSelectableAgentGroups([
      makeGroup({ id: 'active-agent', name: 'Active Agents' }),
      makeGroup({ id: 'archived-agent', name: 'Archived Agents', status: 'ARCHIVED' }),
      makeGroup({ id: 'admin-group', name: 'Admins', level: 'ADMIN' }),
      makeGroup({ id: 'user-group', name: 'Users', level: 'USER' }),
    ]);

    expect(selectable.map((group) => group.id)).toEqual(['active-agent']);
  });
});

describe('AdminInviteManagement rendering', () => {
  it('renders Level options as User / Agent / Admin and does not render Member', () => {
    const html = renderToStaticMarkup(React.createElement(AdminInviteManagement));

    expect(html).toContain('Level');
    expect(html).toContain('value="USER"');
    expect(html).toContain('User');
    expect(html).toContain('value="AGENT"');
    expect(html).toContain('Agent');
    expect(html).toContain('value="ADMIN"');
    expect(html).toContain('Admin');
    expect(html).not.toContain('value="MEMBER"');
    expect(html).not.toContain('Member</option>');
  });

  it('renders an Agent selector with only active Agent groups and selected group names', () => {
    const html = renderToStaticMarkup(
      React.createElement(AdminInviteAgentGroupSelector, {
        loading: false,
        error: null,
        groups: [
          makeGroup({ id: 'group-1', name: 'HR Agents' }),
          makeGroup({ id: 'group-2', name: 'Archived Agents', status: 'ARCHIVED' }),
          makeGroup({ id: 'group-3', name: 'Admin Group', level: 'ADMIN' }),
        ],
        selectedGroupIds: ['group-1'],
        disabled: false,
        onToggleGroup: () => undefined,
      }),
    );

    expect(html).toContain('HR Agents');
    expect(html).toContain('Selected Agent groups:');
    expect(html).not.toContain('Archived Agents');
    expect(html).not.toContain('Admin Group');
    expect(html).toContain('provisioning context only');
    expect(html).not.toContain('has operational access');
  });

  it('renders the no-active-Agent-groups empty state', () => {
    const html = renderToStaticMarkup(
      React.createElement(AdminInviteAgentGroupSelector, {
        loading: false,
        error: null,
        groups: [makeGroup({ id: 'group-1', level: 'USER', name: 'Users' })],
        selectedGroupIds: [],
        disabled: false,
        onToggleGroup: () => undefined,
      }),
    );

    expect(html).toContain(
      'Create an active Agent group in People &amp; Teams before inviting an Agent.',
    );
    expect(html).toContain('/admin/settings/people-teams');
  });
});
