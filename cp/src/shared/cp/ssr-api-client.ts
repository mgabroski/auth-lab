/**
 * cp/src/shared/cp/ssr-api-client.ts
 *
 * WHY:
 * - CP Server Components call the backend directly via INTERNAL_API_URL
 *   (container-to-container, bypassing the public proxy).
 * - Mirrors the locked SSR/internal-backend contract already used by the tenant app.
 *
 * RULES:
 * - Used ONLY in Server Components and Route Handlers inside the CP package.
 * - Never import this in Client Components (use same-origin /api/* there).
 * - cache: 'no-store' — CP operator data is never cacheable.
 *
 * CP AUTH NOTE:
 * - CP is dev-only no-auth in this phase.
 * - Cookie forwarding is intentionally omitted for now because there is no CP
 *   session model yet.
 * - Host and X-Forwarded-* context are still forwarded so later auth/RBAC work
 *   does not require a topology rewrite.
 */

import { randomUUID } from 'node:crypto';
import { headers } from 'next/headers';

function resolveRequestId(incomingHeaders: Headers): string {
  return (
    incomingHeaders.get('x-request-id') ?? incomingHeaders.get('x-correlation-id') ?? randomUUID()
  );
}

function resolveInternalApiUrl(): string {
  return (process.env.INTERNAL_API_URL ?? 'http://localhost:3001').replace(/\/+$/g, '');
}

export async function cpSsrFetch(path: string, init?: RequestInit): Promise<Response> {
  const incomingHeaders = await headers();

  const host = incomingHeaders.get('host') ?? '';
  const forwardedHost = incomingHeaders.get('x-forwarded-host') ?? host;
  const forwardedFor = incomingHeaders.get('x-forwarded-for') ?? '';
  const proto = incomingHeaders.get('x-forwarded-proto') ?? 'http';
  const userAgent = incomingHeaders.get('user-agent') ?? '';
  const requestId = resolveRequestId(incomingHeaders);

  const internalUrl = resolveInternalApiUrl();
  const targetUrl = `${internalUrl}${path}`;

  const outgoingHeaders = new Headers(init?.headers);

  if (host) {
    outgoingHeaders.set('Host', host);
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

  return fetch(targetUrl, {
    ...init,
    method,
    headers: outgoingHeaders,
    cache: 'no-store',
  });
}
