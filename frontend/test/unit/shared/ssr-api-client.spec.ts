import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const {
  headersMock,
  cookiesMock,
  randomUUIDMock,
  serverLoggerErrorMock,
  serverLoggerInfoMock,
  serverLoggerWarnMock,
} = vi.hoisted(() => ({
  headersMock: vi.fn(),
  cookiesMock: vi.fn(),
  randomUUIDMock: vi.fn(),
  serverLoggerErrorMock: vi.fn(),
  serverLoggerInfoMock: vi.fn(),
  serverLoggerWarnMock: vi.fn(),
}));

vi.mock('next/headers', () => ({
  headers: headersMock,
  cookies: cookiesMock,
}));

vi.mock('node:crypto', () => ({
  randomUUID: randomUUIDMock,
}));

vi.mock('@/shared/server/logger', () => ({
  serverLogger: {
    error: serverLoggerErrorMock,
    info: serverLoggerInfoMock,
    warn: serverLoggerWarnMock,
  },
}));

import { ssrFetch } from '../../../src/shared/ssr-api-client';

beforeEach(() => {
  process.env.INTERNAL_API_URL = 'http://internal-backend:3001';
  randomUUIDMock.mockReturnValue('generated-request-id-001');
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();

  headersMock.mockReset();
  cookiesMock.mockReset();
  randomUUIDMock.mockReset();
  serverLoggerErrorMock.mockReset();
  serverLoggerInfoMock.mockReset();
  serverLoggerWarnMock.mockReset();

  delete process.env.INTERNAL_API_URL;
});

describe('ssrFetch', () => {
  it('forwards topology headers, cookies, user-agent, and inbound x-request-id', async () => {
    headersMock.mockResolvedValue(
      new Headers({
        host: 'goodwill-ca.lvh.me:3000',
        'x-forwarded-for': '10.0.0.1',
        'x-forwarded-proto': 'https',
        'user-agent': 'VitestAgent/1.0',
        'x-request-id': 'existing-request-id-001',
      }),
    );

    cookiesMock.mockResolvedValue({
      getAll: () => [
        { name: 'sid', value: 'session-cookie' },
        { name: 'theme', value: 'dark' },
      ],
    });

    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);

    await ssrFetch('/auth/me');

    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://internal-backend:3001/auth/me');
    expect(init.method).toBe('GET');
    expect(init.cache).toBe('no-store');

    const forwardedHeaders = init.headers as Headers;

    expect(forwardedHeaders.get('Host')).toBe('goodwill-ca.lvh.me:3000');
    expect(forwardedHeaders.get('Cookie')).toBe('sid=session-cookie; theme=dark');
    expect(forwardedHeaders.get('X-Forwarded-For')).toBe('10.0.0.1');
    expect(forwardedHeaders.get('X-Forwarded-Proto')).toBe('https');
    expect(forwardedHeaders.get('X-Forwarded-Host')).toBe('goodwill-ca.lvh.me:3000');
    expect(forwardedHeaders.get('User-Agent')).toBe('VitestAgent/1.0');
    expect(forwardedHeaders.get('X-Request-Id')).toBe('existing-request-id-001');
    expect(forwardedHeaders.get('Accept')).toBe('application/json');
    expect(forwardedHeaders.get('Content-Type')).toBeNull();

    expect(randomUUIDMock).not.toHaveBeenCalled();
  });

  it('generates a request id when none is present and sets Content-Type when body is present', async () => {
    headersMock.mockResolvedValue(
      new Headers({
        host: 'goodwill-open.lvh.me:3000',
      }),
    );

    cookiesMock.mockResolvedValue({
      getAll: () => [],
    });

    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
        },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await ssrFetch('/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email: 'user@example.com',
        password: 'Password123!',
      }),
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://internal-backend:3001/auth/login');
    expect(init.method).toBe('POST');
    expect(init.cache).toBe('no-store');

    const forwardedHeaders = init.headers as Headers;

    expect(forwardedHeaders.get('Host')).toBe('goodwill-open.lvh.me:3000');
    expect(forwardedHeaders.get('X-Forwarded-Proto')).toBe('http');
    expect(forwardedHeaders.get('X-Forwarded-Host')).toBe('goodwill-open.lvh.me:3000');
    expect(forwardedHeaders.get('X-Request-Id')).toBe('generated-request-id-001');
    expect(forwardedHeaders.get('Content-Type')).toBe('application/json');
    expect(randomUUIDMock).toHaveBeenCalledTimes(1);
  });

  it('logs and rethrows backend transport failures from SSR paths', async () => {
    headersMock.mockResolvedValue(
      new Headers({
        host: 'goodwill-ca.lvh.me:3000',
        'x-request-id': 'transport-request-id-001',
      }),
    );

    cookiesMock.mockResolvedValue({
      getAll: () => [],
    });

    const transportError = new Error('backend down');
    const fetchMock = vi.fn().mockRejectedValue(transportError);
    vi.stubGlobal('fetch', fetchMock);

    await expect(ssrFetch('/auth/config')).rejects.toThrow('backend down');

    expect(serverLoggerErrorMock).toHaveBeenCalledWith(
      'ssr.api.transport_failed',
      expect.objectContaining({
        event: 'ssr.api.transport_failed',
        flow: 'ssr.api',
        requestId: 'transport-request-id-001',
        method: 'GET',
        path: '/auth/config',
        targetUrl: 'http://internal-backend:3001/auth/config',
        error: transportError,
      }),
    );
  });
});
