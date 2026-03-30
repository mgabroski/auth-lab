import { afterEach, describe, expect, it, vi } from 'vitest';
import type { NextRequest } from 'next/server';

import { GET, HEAD, POST } from '../../../src/app/api/[...path]/route';

type RouteContext = {
  params: Promise<{
    path: string[];
  }>;
};

function makeContext(path: string[]): RouteContext {
  return {
    params: Promise.resolve({ path }),
  };
}

function makeArrayBuffer(value?: string): ArrayBuffer {
  const bytes = new TextEncoder().encode(value ?? '');
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function makeRequest(opts: {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
}): NextRequest {
  return {
    method: opts.method,
    nextUrl: new URL(opts.url),
    headers: new Headers(opts.headers),
    arrayBuffer: () => Promise.resolve(makeArrayBuffer(opts.body)),
  } as unknown as NextRequest;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  delete process.env.INTERNAL_API_URL;
});

describe('frontend api proxy route', () => {
  it('proxies GET requests to INTERNAL_API_URL, preserves tenant-bearing headers, and passes upstream response headers back', async () => {
    process.env.INTERNAL_API_URL = 'http://backend-internal:4000/';

    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'set-cookie': 'sid=session-123; Path=/; HttpOnly',
          'x-upstream': 'kept',
          connection: 'close',
        },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const request = makeRequest({
      method: 'GET',
      url: 'http://goodwill-ca.lvh.me:3000/api/auth/me?include=tenant',
      headers: {
        host: 'goodwill-ca.lvh.me:3000',
        cookie: 'sid=session-123',
        'x-forwarded-for': '203.0.113.10',
        'x-forwarded-proto': 'https',
        'x-custom-header': 'preserved',
        connection: 'keep-alive',
      },
    });

    const response = await GET(request, makeContext(['auth', 'me']));

    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [calledUrl, calledInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    const calledHeaders = new Headers(calledInit.headers);

    expect(calledUrl).toBe('http://backend-internal:4000/auth/me?include=tenant');
    expect(calledInit.method).toBe('GET');
    expect(calledInit.cache).toBe('no-store');
    expect(calledInit.redirect).toBe('manual');
    expect(calledInit.body).toBeUndefined();

    expect(calledHeaders.get('host')).toBe('goodwill-ca.lvh.me:3000');
    expect(calledHeaders.get('x-forwarded-host')).toBe('goodwill-ca.lvh.me:3000');
    expect(calledHeaders.get('x-forwarded-proto')).toBe('https');
    expect(calledHeaders.get('x-forwarded-for')).toBe('203.0.113.10');
    expect(calledHeaders.get('cookie')).toBe('sid=session-123');
    expect(calledHeaders.get('x-custom-header')).toBe('preserved');
    expect(calledHeaders.get('connection')).toBeNull();

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('application/json');
    expect(response.headers.get('x-upstream')).toBe('kept');
    expect(response.headers.get('set-cookie')).toBe('sid=session-123; Path=/; HttpOnly');
    expect(response.headers.get('connection')).toBeNull();
    expect(await response.json()).toEqual({ ok: true });
  });

  it('proxies POST requests, strips hop-by-hop request headers, forwards request body, and falls back to nextUrl.protocol when x-forwarded-proto is missing', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(null, {
        status: 204,
        headers: {
          'x-upstream': 'write-ok',
        },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const body = JSON.stringify({
      email: 'user@example.com',
      password: 'Password123!',
    });

    const request = makeRequest({
      method: 'POST',
      url: 'http://tenant-b.lvh.me:3000/api/auth/login?mode=password',
      headers: {
        host: 'tenant-b.lvh.me:3000',
        'content-type': 'application/json',
        'content-length': '999',
        connection: 'keep-alive',
        'x-real-ip': '198.51.100.7',
        cookie: 'sid=existing-session',
      },
      body,
    });

    const response = await POST(request, makeContext(['auth', 'login']));

    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [calledUrl, calledInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    const calledHeaders = new Headers(calledInit.headers);

    expect(calledUrl).toBe('http://localhost:3001/auth/login?mode=password');
    expect(calledInit.method).toBe('POST');
    expect(calledInit.cache).toBe('no-store');
    expect(calledInit.redirect).toBe('manual');

    expect(calledHeaders.get('host')).toBe('tenant-b.lvh.me:3000');
    expect(calledHeaders.get('x-forwarded-host')).toBe('tenant-b.lvh.me:3000');
    expect(calledHeaders.get('x-forwarded-proto')).toBe('http');
    expect(calledHeaders.get('x-forwarded-for')).toBe('198.51.100.7');
    expect(calledHeaders.get('content-type')).toBe('application/json');
    expect(calledHeaders.get('cookie')).toBe('sid=existing-session');
    expect(calledHeaders.get('content-length')).toBeNull();
    expect(calledHeaders.get('connection')).toBeNull();

    const forwardedBody = calledInit.body as ArrayBuffer;
    expect(new TextDecoder().decode(forwardedBody)).toBe(body);

    expect(response.status).toBe(204);
    expect(response.headers.get('x-upstream')).toBe('write-ok');
  });

  it('returns an empty downstream body for HEAD requests', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response('upstream-body-should-not-be-sent', {
        status: 200,
        headers: {
          'x-upstream': 'head-ok',
        },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const request = makeRequest({
      method: 'HEAD',
      url: 'http://goodwill-open.lvh.me:3000/api/auth/config',
      headers: {
        host: 'goodwill-open.lvh.me:3000',
      },
    });

    const response = await HEAD(request, makeContext(['auth', 'config']));

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(response.status).toBe(200);
    expect(response.headers.get('x-upstream')).toBe('head-ok');
    expect(await response.text()).toBe('');
  });
});
