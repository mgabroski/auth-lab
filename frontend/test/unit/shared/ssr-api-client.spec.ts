import { afterEach, describe, expect, it, vi } from 'vitest';

const { cookiesMock, headersMock } = vi.hoisted(() => ({
  headersMock: vi.fn(),
  cookiesMock: vi.fn(),
}));

vi.mock('next/headers', () => ({
  headers: headersMock,
  cookies: cookiesMock,
}));

import { ssrFetch } from '../../../src/shared/ssr-api-client';

function makeRequestHeaders(values: Record<string, string>): Headers {
  return new Headers(values);
}

function makeCookieStore(values: Array<{ name: string; value: string }>) {
  return {
    getAll: () => values,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  headersMock.mockReset();
  cookiesMock.mockReset();
  delete process.env.INTERNAL_API_URL;
});

describe('ssrFetch', () => {
  it('forwards tenant + session headers to the default internal backend URL with cache disabled', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);

    headersMock.mockResolvedValue(
      makeRequestHeaders({
        host: 'goodwill-open.lvh.me:3000',
        'x-forwarded-for': '203.0.113.5',
        'x-forwarded-proto': 'https',
      }),
    );
    cookiesMock.mockResolvedValue(
      makeCookieStore([
        { name: 'sid', value: 'session-123' },
        { name: 'csrf', value: 'csrf-456' },
      ]),
    );

    await ssrFetch('/auth/me');

    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [calledUrl, calledInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    const calledHeaders = new Headers(calledInit.headers);

    expect(calledUrl).toBe('http://backend:3001/auth/me');
    expect(calledInit.cache).toBe('no-store');
    expect(calledHeaders.get('Host')).toBe('goodwill-open.lvh.me:3000');
    expect(calledHeaders.get('Cookie')).toBe('sid=session-123; csrf=csrf-456');
    expect(calledHeaders.get('X-Forwarded-For')).toBe('203.0.113.5');
    expect(calledHeaders.get('X-Forwarded-Proto')).toBe('https');
    expect(calledHeaders.get('X-Forwarded-Host')).toBe('goodwill-open.lvh.me:3000');
    expect(calledHeaders.get('Content-Type')).toBeNull();
  });

  it('uses INTERNAL_API_URL when provided', async () => {
    process.env.INTERNAL_API_URL = 'http://backend-internal:4000';

    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    headersMock.mockResolvedValue(
      makeRequestHeaders({
        host: 'goodwill-ca.lvh.me:3000',
      }),
    );
    cookiesMock.mockResolvedValue(makeCookieStore([]));

    await ssrFetch('/auth/config');

    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [calledUrl, calledInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    const calledHeaders = new Headers(calledInit.headers);

    expect(calledUrl).toBe('http://backend-internal:4000/auth/config');
    expect(calledHeaders.get('Host')).toBe('goodwill-ca.lvh.me:3000');
    expect(calledHeaders.get('Cookie')).toBe('');
    expect(calledHeaders.get('X-Forwarded-Proto')).toBe('http');
  });

  it('preserves caller headers but does not allow overriding forwarded topology headers', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    headersMock.mockResolvedValue(
      makeRequestHeaders({
        host: 'tenant-a.lvh.me:3000',
        'x-forwarded-for': '198.51.100.10',
        'x-forwarded-proto': 'https',
      }),
    );
    cookiesMock.mockResolvedValue(makeCookieStore([{ name: 'sid', value: 'real-session' }]));

    await ssrFetch('/auth/workspace-setup-ack', {
      method: 'POST',
      body: JSON.stringify({ acknowledged: true }),
      headers: {
        'X-Test-Header': 'kept',
        'Content-Type': 'application/merge-patch+json',
        Host: 'malicious-host.example.com',
        Cookie: 'sid=fake-session',
        'X-Forwarded-For': '10.0.0.1',
        'X-Forwarded-Proto': 'http',
        'X-Forwarded-Host': 'malicious-host.example.com',
      },
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [, calledInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    const calledHeaders = new Headers(calledInit.headers);

    expect(calledInit.method).toBe('POST');
    expect(calledInit.body).toBe(JSON.stringify({ acknowledged: true }));
    expect(calledInit.cache).toBe('no-store');
    expect(calledHeaders.get('X-Test-Header')).toBe('kept');
    expect(calledHeaders.get('Content-Type')).toBe('application/merge-patch+json');
    expect(calledHeaders.get('Host')).toBe('tenant-a.lvh.me:3000');
    expect(calledHeaders.get('Cookie')).toBe('sid=real-session');
    expect(calledHeaders.get('X-Forwarded-For')).toBe('198.51.100.10');
    expect(calledHeaders.get('X-Forwarded-Proto')).toBe('https');
    expect(calledHeaders.get('X-Forwarded-Host')).toBe('tenant-a.lvh.me:3000');
  });
});
