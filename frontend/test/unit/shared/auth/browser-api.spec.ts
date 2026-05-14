import { afterEach, describe, expect, it, vi } from 'vitest';

const { apiFetchMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn(),
}));

vi.mock('@/shared/api-client', () => ({
  apiFetch: apiFetchMock,
}));

import { createAdminInvite, listAdminInvites } from '../../../../src/shared/auth/browser-api';

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

describe('auth browser api admin invites', () => {
  it('creates User and Admin invites with canonical levels and no Agent groups', async () => {
    apiFetchMock
      .mockResolvedValueOnce(
        jsonResponse({ invite: { id: 'invite-user', role: 'USER' } }, { status: 201 }),
      )
      .mockResolvedValueOnce(
        jsonResponse({ invite: { id: 'invite-admin', role: 'ADMIN' } }, { status: 201 }),
      );

    await createAdminInvite({ email: 'user@example.com', role: 'USER' });
    await createAdminInvite({ email: 'admin@example.com', role: 'ADMIN' });

    expect(apiFetchMock).toHaveBeenNthCalledWith(1, '/admin/invites', {
      method: 'POST',
      body: JSON.stringify({ email: 'user@example.com', role: 'USER' }),
    });
    expect(apiFetchMock).toHaveBeenNthCalledWith(2, '/admin/invites', {
      method: 'POST',
      body: JSON.stringify({ email: 'admin@example.com', role: 'ADMIN' }),
    });
  });

  it('creates Agent invites with selected Agent group IDs', async () => {
    apiFetchMock.mockResolvedValueOnce(
      jsonResponse(
        {
          invite: {
            id: 'invite-agent',
            role: 'AGENT',
            agentGroups: [
              {
                id: 'group-1',
                name: 'HR Agents',
                level: 'AGENT',
                status: 'ACTIVE',
              },
            ],
          },
        },
        { status: 201 },
      ),
    );

    const result = await createAdminInvite({
      email: 'agent@example.com',
      role: 'AGENT',
      agentGroupIds: ['group-1'],
    });

    expect(apiFetchMock).toHaveBeenCalledWith('/admin/invites', {
      method: 'POST',
      body: JSON.stringify({
        email: 'agent@example.com',
        role: 'AGENT',
        agentGroupIds: ['group-1'],
      }),
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.invite.agentGroups?.[0]?.name).toBe('HR Agents');
    }
  });

  it('normalizes legacy MEMBER invite responses to User at the compatibility boundary', async () => {
    apiFetchMock.mockResolvedValueOnce(
      jsonResponse({
        invites: [
          {
            id: 'invite-legacy',
            tenantId: 'tenant-1',
            email: 'legacy@example.com',
            role: 'MEMBER',
            status: 'PENDING',
            expiresAt: '2026-05-20T00:00:00.000Z',
            usedAt: null,
            createdAt: '2026-05-14T00:00:00.000Z',
            createdByUserId: 'admin-1',
          },
        ],
        total: 1,
        limit: 20,
        offset: 0,
      }),
    );

    const result = await listAdminInvites({ limit: 20, offset: 0 });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.invites[0]?.role).toBe('USER');
    }
  });

  it('surfaces backend validation errors safely', async () => {
    apiFetchMock.mockResolvedValueOnce(
      jsonResponse(
        {
          error: {
            code: 'ADMIN_INVITE_AGENT_GROUPS_REQUIRED',
            message: 'Agent invites require at least one active Agent group.',
          },
        },
        { status: 400 },
      ),
    );

    const result = await createAdminInvite({ email: 'agent@example.com', role: 'AGENT' });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(400);
      expect(result.error.message).toBe('Agent invites require at least one active Agent group.');
    }
  });
});
