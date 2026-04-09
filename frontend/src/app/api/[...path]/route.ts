/**
 * frontend/src/app/api/[...path]/route.ts
 *
 * WHY:
 * - In host-run mode there is no public reverse proxy in front of Next.js.
 * - Browser code must still use same-origin `/api/*` paths.
 * - This Route Handler proxies those requests to the backend while preserving the
 *   original tenant-bearing Host/Cookie/forwarded-header context.
 *
 * IMPORTANT:
 * - Stack/prod-like topology still routes `/api/*` directly to the backend via Caddy/nginx.
 * - This file is a host-run compatibility shim, not a replacement for the real proxy.
 * - Request bodies are forwarded as the original ReadableStream.
 *   Do not re-buffer into ArrayBuffer/Blob here unless the route must inspect or transform bytes.
 */

import type { NextRequest } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const METHODS_WITHOUT_BODY = new Set(['GET', 'HEAD']);

const REQUEST_HEADERS_TO_DROP = new Set([
  'connection',
  'content-length',
  'host',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

const RESPONSE_HEADERS_TO_DROP = new Set([
  'connection',
  'content-length',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

type RouteContext = {
  params: Promise<{
    path: string[];
  }>;
};

type UpstreamRequestInit = RequestInit & {
  duplex?: 'half';
};

function backendBaseUrl(): string {
  return (process.env.INTERNAL_API_URL ?? 'http://localhost:3001').replace(/\/+$/g, '');
}

function buildUpstreamUrl(request: NextRequest, path: string[]): string {
  const upstreamPath = path.length ? `/${path.join('/')}` : '';
  const search = request.nextUrl.search;
  return `${backendBaseUrl()}${upstreamPath}${search}`;
}

function requestProtocol(request: NextRequest): string {
  const forwardedProto = request.headers.get('x-forwarded-proto');
  if (forwardedProto) return forwardedProto;

  const nextProtocol = request.nextUrl.protocol.replace(/:$/g, '');
  return nextProtocol || 'http';
}

function clientIp(request: NextRequest): string | null {
  return request.headers.get('x-forwarded-for') ?? request.headers.get('x-real-ip') ?? '127.0.0.1';
}

function hasRequestBody(method: string): boolean {
  return !METHODS_WITHOUT_BODY.has(method.toUpperCase());
}

function buildUpstreamHeaders(request: NextRequest): Headers {
  const headers = new Headers();

  request.headers.forEach((value, key) => {
    if (REQUEST_HEADERS_TO_DROP.has(key.toLowerCase())) {
      return;
    }

    headers.set(key, value);
  });

  const originalHost = request.headers.get('host');
  if (originalHost) {
    headers.set('host', originalHost);
    headers.set('x-forwarded-host', originalHost);
  }

  headers.set('x-forwarded-proto', requestProtocol(request));

  const forwardedFor = clientIp(request);
  if (forwardedFor) {
    headers.set('x-forwarded-for', forwardedFor);
  }

  return headers;
}

function buildDownstreamHeaders(upstream: Response): Headers {
  const headers = new Headers();

  upstream.headers.forEach((value, key) => {
    if (RESPONSE_HEADERS_TO_DROP.has(key.toLowerCase()) || key.toLowerCase() === 'set-cookie') {
      return;
    }

    headers.append(key, value);
  });

  const getSetCookie = (upstream.headers as Headers & { getSetCookie?: () => string[] })
    .getSetCookie;
  if (typeof getSetCookie === 'function') {
    for (const cookie of getSetCookie.call(upstream.headers)) {
      headers.append('set-cookie', cookie);
    }
  } else {
    const cookie = upstream.headers.get('set-cookie');
    if (cookie) {
      headers.append('set-cookie', cookie);
    }
  }

  return headers;
}

function mustNotHaveBody(status: number): boolean {
  return status === 204 || status === 205 || status === 304;
}

function buildUpstreamRequestInit(request: NextRequest, headers: Headers): UpstreamRequestInit {
  const init: UpstreamRequestInit = {
    method: request.method,
    headers,
    cache: 'no-store',
    redirect: 'manual',
  };

  if (hasRequestBody(request.method) && request.body) {
    init.body = request.body;
    init.duplex = 'half';
  }

  return init;
}

async function proxy(request: NextRequest, context: RouteContext): Promise<Response> {
  const { path } = await context.params;
  const url = buildUpstreamUrl(request, path);
  const headers = buildUpstreamHeaders(request);

  const upstream = await fetch(url, buildUpstreamRequestInit(request, headers));
  const responseHeaders = buildDownstreamHeaders(upstream);

  const responseBody =
    request.method === 'HEAD' || mustNotHaveBody(upstream.status) ? null : upstream.body;

  return new Response(responseBody, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: responseHeaders,
  });
}

export function GET(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}

export function POST(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}

export function PUT(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}

export function PATCH(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}

export function DELETE(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}

export function OPTIONS(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}

export function HEAD(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}
