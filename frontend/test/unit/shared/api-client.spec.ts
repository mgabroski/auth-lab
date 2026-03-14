import { afterEach, describe, expect, it, vi } from 'vitest';

import { apiFetch } from '../../../src/shared/api-client';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('apiFetch', () => {
  it('always uses same-origin /api/* paths with credentials included', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);

    await apiFetch('/auth/me', { method: 'GET' });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith('/api/auth/me', {
      method: 'GET',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
      },
    });
  });

  it('preserves caller-provided headers while still forcing the same-origin cookie discipline', async () => {
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
});
