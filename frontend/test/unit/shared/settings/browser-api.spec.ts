import { afterEach, describe, expect, it, vi } from 'vitest';

const { apiFetchMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn(),
}));

vi.mock('@/shared/api-client', () => ({
  apiFetch: apiFetchMock,
}));

import {
  acknowledgeAccessSettings,
  saveAccountBranding,
  saveAccountCalendar,
  saveAccountOrgStructure,
} from '../../../../src/shared/settings/browser-api';

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

  it('puts the Branding payload to the same-origin account endpoint', async () => {
    apiFetchMock.mockResolvedValueOnce(
      jsonResponse({
        section: {
          key: 'account',
          status: 'IN_PROGRESS',
          version: 2,
          cpRevision: 4,
        },
        card: {
          key: 'branding',
          status: 'COMPLETE',
          version: 2,
          cpRevision: 4,
        },
        aggregate: {
          status: 'IN_PROGRESS',
          version: 2,
          cpRevision: 4,
          nextAction: {
            key: 'access',
            label: 'Review Access & Security',
            href: '/admin/settings/access',
          },
        },
        warnings: [],
      }),
    );

    const result = await saveAccountBranding({
      expectedVersion: 1,
      expectedCpRevision: 4,
      values: {
        logoUrl: 'https://cdn.example.com/logo.svg',
        menuColor: '#0f172a',
        fontColor: '#ffffff',
        welcomeMessage: 'Welcome',
      },
    });

    expect(apiFetchMock).toHaveBeenCalledWith('/settings/account/branding', {
      method: 'PUT',
      body: JSON.stringify({
        expectedVersion: 1,
        expectedCpRevision: 4,
        values: {
          logoUrl: 'https://cdn.example.com/logo.svg',
          menuColor: '#0f172a',
          fontColor: '#ffffff',
          welcomeMessage: 'Welcome',
        },
      }),
    });
    expect(result.ok).toBe(true);
  });

  it('puts the Organization Structure payload to the same-origin account endpoint', async () => {
    apiFetchMock.mockResolvedValueOnce(
      jsonResponse({
        section: {
          key: 'account',
          status: 'IN_PROGRESS',
          version: 2,
          cpRevision: 4,
        },
        card: {
          key: 'orgStructure',
          status: 'COMPLETE',
          version: 2,
          cpRevision: 4,
        },
        aggregate: {
          status: 'IN_PROGRESS',
          version: 2,
          cpRevision: 4,
          nextAction: {
            key: 'access',
            label: 'Review Access & Security',
            href: '/admin/settings/access',
          },
        },
        warnings: [],
      }),
    );

    const result = await saveAccountOrgStructure({
      expectedVersion: 1,
      expectedCpRevision: 4,
      values: {
        employers: ['Acme'],
        locations: ['Skopje'],
      },
    });

    expect(apiFetchMock).toHaveBeenCalledWith('/settings/account/org-structure', {
      method: 'PUT',
      body: JSON.stringify({
        expectedVersion: 1,
        expectedCpRevision: 4,
        values: {
          employers: ['Acme'],
          locations: ['Skopje'],
        },
      }),
    });
    expect(result.ok).toBe(true);
  });

  it('puts the Company Calendar payload to the same-origin account endpoint', async () => {
    apiFetchMock.mockResolvedValueOnce(
      jsonResponse({
        section: {
          key: 'account',
          status: 'IN_PROGRESS',
          version: 2,
          cpRevision: 4,
        },
        card: {
          key: 'calendar',
          status: 'COMPLETE',
          version: 2,
          cpRevision: 4,
        },
        aggregate: {
          status: 'IN_PROGRESS',
          version: 2,
          cpRevision: 4,
          nextAction: {
            key: 'access',
            label: 'Review Access & Security',
            href: '/admin/settings/access',
          },
        },
        warnings: [],
      }),
    );

    const result = await saveAccountCalendar({
      expectedVersion: 1,
      expectedCpRevision: 4,
      values: {
        observedDates: ['2026-01-01'],
      },
    });

    expect(apiFetchMock).toHaveBeenCalledWith('/settings/account/calendar', {
      method: 'PUT',
      body: JSON.stringify({
        expectedVersion: 1,
        expectedCpRevision: 4,
        values: {
          observedDates: ['2026-01-01'],
        },
      }),
    });
    expect(result.ok).toBe(true);
  });
});
