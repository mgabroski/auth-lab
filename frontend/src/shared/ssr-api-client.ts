/**
 * src/shared/ssr-api-client.ts
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
 * - Callers may add extra headers, but must never override the forwarded
 *   topology/session headers required for tenant resolution.
 */

import { cookies, headers } from 'next/headers';

function buildInvariantHeaders(args: {
  host: string;
  cookie: string;
  forwardedFor: string;
  forwardedProto: string;
}): Headers {
  const result = new Headers();

  result.set('Host', args.host);
  result.set('Cookie', args.cookie);
  result.set('X-Forwarded-For', args.forwardedFor);
  result.set('X-Forwarded-Proto', args.forwardedProto);
  result.set('X-Forwarded-Host', args.host);

  return result;
}

export async function ssrFetch(path: string, init?: RequestInit): Promise<Response> {
  const incomingHeaders = await headers();
  const incomingCookies = await cookies();

  const host = incomingHeaders.get('host') ?? '';
  const forwardedFor = incomingHeaders.get('x-forwarded-for') ?? '';
  const forwardedProto = incomingHeaders.get('x-forwarded-proto') ?? 'http';

  const cookieHeader = incomingCookies
    .getAll()
    .map((cookie) => `${cookie.name}=${cookie.value}`)
    .join('; ');

  const outgoingHeaders = new Headers(init?.headers);

  if (init?.body !== undefined && !outgoingHeaders.has('Content-Type')) {
    outgoingHeaders.set('Content-Type', 'application/json');
  }

  const invariantHeaders = buildInvariantHeaders({
    host,
    cookie: cookieHeader,
    forwardedFor,
    forwardedProto,
  });

  for (const [name, value] of invariantHeaders.entries()) {
    outgoingHeaders.set(name, value);
  }

  const internalUrl = process.env.INTERNAL_API_URL ?? 'http://backend:3001';

  return fetch(`${internalUrl}${path}`, {
    ...init,
    headers: outgoingHeaders,
    cache: 'no-store',
  });
}
