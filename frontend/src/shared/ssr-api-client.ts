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
 */

import { headers, cookies } from 'next/headers';

export async function ssrFetch(path: string, init?: RequestInit): Promise<Response> {
  const incomingHeaders = await headers();
  const incomingCookies = await cookies();

  const host = incomingHeaders.get('host') ?? '';
  const fwdFor = incomingHeaders.get('x-forwarded-for') ?? '';
  const proto = incomingHeaders.get('x-forwarded-proto') ?? 'http';

  const cookieStr = incomingCookies
    .getAll()
    .map((c) => `${c.name}=${c.value}`)
    .join('; ');

  const internalUrl = process.env.INTERNAL_API_URL ?? 'http://backend:3001';

  return fetch(`${internalUrl}${path}`, {
    ...init,
    headers: {
      Host: host,
      Cookie: cookieStr,
      'X-Forwarded-For': fwdFor,
      'X-Forwarded-Proto': proto,
      'X-Forwarded-Host': host,
      'Content-Type': 'application/json',
      ...init?.headers,
    },
    cache: 'no-store',
  });
}
