/**
 * frontend/src/shared/ssr-api-client.ts
 *
 * WHY:
 * - SSR server components call the backend directly via INTERNAL_API_URL
 *   (container-to-container, bypassing the proxy).
 * - Must forward Host + Cookie + X-Forwarded-* headers explicitly so the
 *   backend's tenant resolution and session middleware work correctly.
 *
 * RULES:
 * - Used ONLY in Server Components, layouts, Route Handlers.
 * - Never used in Client Components (use api-client.ts there).
 * - cache: 'no-store' — session data is never cacheable.
 *
 * STAGE 3:
 * - Propagates x-request-id across frontend SSR/server → backend.
 * - Logs upstream transport failures from frontend server paths.
 */

import { randomUUID } from 'node:crypto';
import { headers, cookies } from 'next/headers';

import { serverLogger } from '@/shared/server/logger';

function resolveRequestId(incomingHeaders: Headers): string {
  return (
    incomingHeaders.get('x-request-id') ?? incomingHeaders.get('x-correlation-id') ?? randomUUID()
  );
}

export async function ssrFetch(path: string, init?: RequestInit): Promise<Response> {
  const incomingHeaders = await headers();
  const incomingCookies = await cookies();

  const host = incomingHeaders.get('host') ?? '';
  const forwardedHost = incomingHeaders.get('x-forwarded-host') ?? host;
  const forwardedFor = incomingHeaders.get('x-forwarded-for') ?? '';
  const proto = incomingHeaders.get('x-forwarded-proto') ?? 'http';
  const userAgent = incomingHeaders.get('user-agent') ?? '';
  const requestId = resolveRequestId(incomingHeaders);

  const cookieStr = incomingCookies
    .getAll()
    .map((c) => `${c.name}=${c.value}`)
    .join('; ');

  const internalUrl = (process.env.INTERNAL_API_URL ?? 'http://backend:3001').replace(/\/+$/g, '');
  const targetUrl = `${internalUrl}${path}`;

  const outgoingHeaders = new Headers(init?.headers);

  if (host) {
    outgoingHeaders.set('Host', host);
  }

  if (cookieStr) {
    outgoingHeaders.set('Cookie', cookieStr);
  }

  if (forwardedFor) {
    outgoingHeaders.set('X-Forwarded-For', forwardedFor);
  }

  outgoingHeaders.set('X-Forwarded-Proto', proto);

  if (forwardedHost) {
    outgoingHeaders.set('X-Forwarded-Host', forwardedHost);
  }

  if (userAgent) {
    outgoingHeaders.set('User-Agent', userAgent);
  }

  outgoingHeaders.set('X-Request-Id', requestId);

  if (!outgoingHeaders.has('Accept')) {
    outgoingHeaders.set('Accept', 'application/json');
  }

  const method = (init?.method ?? 'GET').toUpperCase();
  const hasBody = init?.body !== undefined && init?.body !== null;

  if (hasBody && !outgoingHeaders.has('Content-Type')) {
    outgoingHeaders.set('Content-Type', 'application/json');
  }

  try {
    return await fetch(targetUrl, {
      ...init,
      method,
      headers: outgoingHeaders,
      cache: 'no-store',
    });
  } catch (error) {
    serverLogger.error('ssr.api.transport_failed', {
      event: 'ssr.api.transport_failed',
      flow: 'ssr.api',
      requestId,
      method,
      path,
      targetUrl,
      error,
    });

    throw error;
  }
}
