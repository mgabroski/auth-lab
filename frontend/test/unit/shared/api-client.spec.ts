import { afterEach, describe, expect, it, vi } from 'vitest';

import { apiFetch } from '../../../src/shared/api-client';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('apiFetch', () => {
  it('uses same-origin /api/* paths with credentials — no Content-Type when no body', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);

    await apiFetch('/auth/me', { method: 'GET' });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith('/api/auth/me', {
      method: 'GET',
      credentials: 'include',
      // Content-Type is intentionally absent — no body means no content type.
      // Fastify rejects requests with Content-Type: application/json but empty
      // body. GET requests and parameterless POSTs (setupMfa, logout) must not
      // set this header.
      headers: {},
    });
  });

  it('sets Content-Type: application/json and preserves caller headers when body is present', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    await apiFetch('/auth/login', {
      method: 'POST',
      headers: {
        'X-Test-Header': 'frontend-discipline',
      },
      body: JSON.stringify({
        email: 'user@example.com',
        password: 'Password123!',
      }),
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith('/api/auth/login', {
      method: 'POST',
      credentials: 'include',
      body: JSON.stringify({
        email: 'user@example.com',
        password: 'Password123!',
      }),
      headers: {
        'Content-Type': 'application/json',
        'X-Test-Header': 'frontend-discipline',
      },
    });
  });

  it('does not set Content-Type for a parameterless POST (setupMfa / logout pattern)', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    await apiFetch('/auth/mfa/setup', { method: 'POST' });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, calledInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect((calledInit.headers as Record<string, string>)['Content-Type']).toBeUndefined();
  });
});
