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
 * - Request bodies are forwarded as Blob instances created from request.arrayBuffer().
 *   This avoids unstable direct stream forwarding and keeps RequestInit.body compatible
 *   with the TypeScript/body contract in this repo.
 * - Tenant-host /api/cp/* must be blocked here so the host-run compatibility
 *   shim cannot reopen the Control Plane backend surface outside the CP app.
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

function isControlPlanePath(path: string[]): boolean {
  return path[0] === 'cp';
}

function buildBlockedControlPlaneResponse(method: string): Response {
  const headers = new Headers({
    'content-type': 'application/json',
  });

  const body =
    method.toUpperCase() === 'HEAD'
      ? null
      : JSON.stringify({
          error: {
            code: 'NOT_FOUND',
            message: 'Not found',
          },
        });

  return new Response(body, {
    status: 404,
    headers,
  });
}

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

function clientIp(request: NextRequest): string {
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
  headers.set('x-forwarded-for', clientIp(request));

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

async function buildUpstreamBody(request: NextRequest): Promise<Blob | undefined> {
  if (!hasRequestBody(request.method)) {
    return undefined;
  }

  const buffer = await request.arrayBuffer();
  if (buffer.byteLength === 0) {
    return undefined;
  }

  return new Blob([buffer]);
}

async function proxy(request: NextRequest, context: RouteContext): Promise<Response> {
  const { path } = await context.params;

  if (isControlPlanePath(path)) {
    return buildBlockedControlPlaneResponse(request.method);
  }

  const url = buildUpstreamUrl(request, path);
  const headers = buildUpstreamHeaders(request);
  const body = await buildUpstreamBody(request);

  const upstream = await fetch(url, {
    method: request.method,
    headers,
    body,
    cache: 'no-store',
    redirect: 'manual',
  });

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
