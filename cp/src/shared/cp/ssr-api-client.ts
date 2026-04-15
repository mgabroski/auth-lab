/**
 * cp/src/shared/cp/ssr-api-client.ts
 *
 * WHY:
 * - CP Server Components call the backend directly via INTERNAL_API_URL
 *   (container-to-container, bypassing the proxy).
 * - Mirrors the pattern in frontend/src/shared/ssr-api-client.ts.
 *
 * RULES:
 * - Used ONLY in Server Components and Route Handlers inside the CP package.
 * - Never import this in Client Components (use /api/* proxy routes there).
 * - cache: 'no-store' — CP operator data is never cacheable.
 *
 * CP AUTH NOTE:
 * - CP is dev-only no-auth in this phase.
 * - No Cookie forwarding for sessions is needed yet.
 * - The client is structured to accept additional headers in a later phase
 *   when CP authentication is added (auth header injection point is clear).
 *
 * BACKEND ORIGIN:
 * - Reads INTERNAL_API_URL from the process environment.
 * - Falls back to http://localhost:3001 for local host-run mode.
 * - Never hardcoded to a specific origin in application code.
 */

import { randomUUID } from 'node:crypto';

function resolveInternalApiUrl(): string {
  return (process.env.INTERNAL_API_URL ?? 'http://localhost:3001').replace(/\/+$/g, '');
}

export async function cpSsrFetch(path: string, init?: RequestInit): Promise<Response> {
  const requestId = randomUUID();
  const internalUrl = resolveInternalApiUrl();
  const targetUrl = `${internalUrl}${path}`;

  const outgoingHeaders = new Headers(init?.headers);

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
