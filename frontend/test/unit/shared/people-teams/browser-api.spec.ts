import { afterEach, describe, expect, it, vi } from 'vitest';

const { apiFetchMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn(),
}));

vi.mock('@/shared/api-client', () => ({
  apiFetch: apiFetchMock,
}));

import {
  addPeopleTeamGroupMember,
  archivePeopleTeamGroup,
  createPeopleTeamGroup,
  fetchPeopleTeamGroupMembersBrowser,
  fetchPeopleTeamGroupsBrowser,
  fetchPeopleTeamPeopleBrowser,
  removePeopleTeamGroupMember,
  updatePeopleTeamGroup,
} from '../../../../src/shared/people-teams/browser-api';

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: init?.status ?? 200,
    statusText: init?.statusText,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  });
}

afterEach(() => {
  apiFetchMock.mockReset();
});

describe('people teams browser api', () => {
  it('calls group and people read endpoints through the same-origin proxy', async () => {
    apiFetchMock
      .mockResolvedValueOnce(jsonResponse({ groups: [] }))
      .mockResolvedValueOnce(jsonResponse({ people: [] }))
      .mockResolvedValueOnce(jsonResponse({ members: [] }));

    await expect(fetchPeopleTeamGroupsBrowser()).resolves.toMatchObject({ ok: true });
    await expect(fetchPeopleTeamPeopleBrowser()).resolves.toMatchObject({ ok: true });
    await expect(fetchPeopleTeamGroupMembersBrowser('group-1')).resolves.toMatchObject({
      ok: true,
    });

    expect(apiFetchMock).toHaveBeenNthCalledWith(1, '/people-teams/groups', { method: 'GET' });
    expect(apiFetchMock).toHaveBeenNthCalledWith(2, '/people-teams/people', { method: 'GET' });
    expect(apiFetchMock).toHaveBeenNthCalledWith(3, '/people-teams/groups/group-1/members', {
      method: 'GET',
    });
  });

  it('calls group lifecycle write endpoints with backend-owned payloads', async () => {
    apiFetchMock
      .mockResolvedValueOnce(jsonResponse({ group: { id: 'group-1' } }, { status: 201 }))
      .mockResolvedValueOnce(jsonResponse({ group: { id: 'group-1' } }))
      .mockResolvedValueOnce(jsonResponse({ group: { id: 'group-1' } }));

    await createPeopleTeamGroup({ name: 'HR Agents', description: null, level: 'AGENT' });
    await updatePeopleTeamGroup('group-1', {
      name: 'People Team',
      description: 'Updated',
      level: 'ADMIN',
    });
    await archivePeopleTeamGroup('group-1');

    expect(apiFetchMock).toHaveBeenNthCalledWith(1, '/people-teams/groups', {
      method: 'POST',
      body: JSON.stringify({ name: 'HR Agents', description: null, level: 'AGENT' }),
    });
    expect(apiFetchMock).toHaveBeenNthCalledWith(2, '/people-teams/groups/group-1', {
      method: 'PUT',
      body: JSON.stringify({ name: 'People Team', description: 'Updated', level: 'ADMIN' }),
    });
    expect(apiFetchMock).toHaveBeenNthCalledWith(3, '/people-teams/groups/group-1/archive', {
      method: 'POST',
    });
  });

  it('calls group membership write endpoints without changing runtime roles', async () => {
    apiFetchMock
      .mockResolvedValueOnce(
        jsonResponse({ member: { membershipId: 'membership-1' } }, { status: 201 }),
      )
      .mockResolvedValueOnce(jsonResponse({ member: { membershipId: 'membership-1' } }));

    await addPeopleTeamGroupMember('group-1', { membershipId: 'membership-1' });
    await removePeopleTeamGroupMember('group-1', 'membership-1');

    expect(apiFetchMock).toHaveBeenNthCalledWith(1, '/people-teams/groups/group-1/members', {
      method: 'POST',
      body: JSON.stringify({ membershipId: 'membership-1' }),
    });
    expect(apiFetchMock).toHaveBeenNthCalledWith(
      2,
      '/people-teams/groups/group-1/members/membership-1',
      { method: 'DELETE' },
    );
  });
});
