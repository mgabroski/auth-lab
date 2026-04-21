import { afterEach, describe, expect, it, vi } from 'vitest';

const { apiFetchMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn(),
}));

vi.mock('@/shared/api-client', () => ({
  apiFetch: apiFetchMock,
}));

import { acknowledgeAccessSettings } from '../../../../src/shared/settings/browser-api';

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

describe('settings browser api', () => {
  it('posts the explicit acknowledge payload to the same-origin settings endpoint', async () => {
    apiFetchMock.mockResolvedValueOnce(
      jsonResponse({
        section: {
          key: 'access',
          status: 'COMPLETE',
          version: 2,
          cpRevision: 4,
        },
        aggregate: {
          status: 'IN_PROGRESS',
          version: 2,
          cpRevision: 4,
          nextAction: {
            key: 'modules',
            label: 'Continue Personal setup',
            href: '/admin/settings/modules/personal',
          },
        },
        warnings: [],
      }),
    );

    const result = await acknowledgeAccessSettings({
      expectedVersion: 1,
      expectedCpRevision: 4,
    });

    expect(apiFetchMock).toHaveBeenCalledWith('/settings/access/acknowledge', {
      method: 'POST',
      body: JSON.stringify({
        expectedVersion: 1,
        expectedCpRevision: 4,
      }),
    });
    expect(result.ok).toBe(true);

    if (!result.ok) {
      throw new Error('Expected browser settings success');
    }

    expect(result.data.section.status).toBe('COMPLETE');
    expect(result.data.aggregate.nextAction?.href).toBe('/admin/settings/modules/personal');
  });
});
