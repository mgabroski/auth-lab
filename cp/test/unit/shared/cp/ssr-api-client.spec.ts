import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { headersMock, randomUUIDMock } = vi.hoisted(() => ({
  headersMock: vi.fn(),
  randomUUIDMock: vi.fn(),
}));

vi.mock('next/headers', () => ({
  headers: headersMock,
}));

vi.mock('node:crypto', () => ({
  randomUUID: randomUUIDMock,
}));

import { cpSsrFetch } from '../../../../src/shared/cp/ssr-api-client';

beforeEach(() => {
  process.env.INTERNAL_API_URL = 'http://internal-backend:3001';
  randomUUIDMock.mockReturnValue('generated-request-id-001');
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  headersMock.mockReset();
  randomUUIDMock.mockReset();
  delete process.env.INTERNAL_API_URL;
});

describe('cpSsrFetch', () => {
  it('forwards topology headers and preserves an inbound request id', async () => {
    headersMock.mockResolvedValue(
      new Headers({
        host: 'cp.lvh.me:3000',
        'x-forwarded-for': '203.0.113.10',
        'x-forwarded-proto': 'https',
        'x-forwarded-host': 'cp.lvh.me:3000',
        'user-agent': 'VitestAgent/1.0',
        'x-request-id': 'existing-request-id-001',
      }),
    );

    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);

    await cpSsrFetch('/cp/accounts');

    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://internal-backend:3001/cp/accounts');
    expect(init.method).toBe('GET');
    expect(init.cache).toBe('no-store');

    const headers = init.headers as Headers;
    expect(headers.get('Host')).toBe('cp.lvh.me:3000');
    expect(headers.get('X-Forwarded-For')).toBe('203.0.113.10');
    expect(headers.get('X-Forwarded-Proto')).toBe('https');
    expect(headers.get('X-Forwarded-Host')).toBe('cp.lvh.me:3000');
    expect(headers.get('User-Agent')).toBe('VitestAgent/1.0');
    expect(headers.get('X-Request-Id')).toBe('existing-request-id-001');
    expect(headers.get('Accept')).toBe('application/json');
    expect(headers.get('Content-Type')).toBeNull();
    expect(randomUUIDMock).not.toHaveBeenCalled();
  });

  it('generates a request id and sets JSON content-type when a body is present', async () => {
    headersMock.mockResolvedValue(
      new Headers({
        host: 'cp.lvh.me:3000',
      }),
    );

    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);

    await cpSsrFetch('/cp/accounts', {
      method: 'POST',
      body: JSON.stringify({
        accountName: 'QA Tenant',
      }),
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://internal-backend:3001/cp/accounts');
    expect(init.method).toBe('POST');

    const headers = init.headers as Headers;
    expect(headers.get('X-Forwarded-Proto')).toBe('http');
    expect(headers.get('X-Forwarded-Host')).toBe('cp.lvh.me:3000');
    expect(headers.get('X-Request-Id')).toBe('generated-request-id-001');
    expect(headers.get('Content-Type')).toBe('application/json');
    expect(randomUUIDMock).toHaveBeenCalledTimes(1);
  });
});
