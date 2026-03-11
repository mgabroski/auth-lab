/**
 * src/shared/api-client.ts
 *
 * WHY:
 * - Client components call the backend via same-origin `/api/*` URLs.
 * - In host-run mode, Next.js proxies those requests through `app/api/[...path]/route.ts`.
 * - In stack/prod-like mode, the public reverse proxy routes `/api/*` directly to the backend.
 * - `credentials: 'include'` ensures the session cookie is always sent.
 *
 * RULES:
 * - Used ONLY in Client Components ('use client').
 * - Server components use ssr-api-client.ts instead.
 * - Never hardcode a backend URL. Always relative `/api/*` paths.
 * - Never use fetch() to start SSO — use window.location.href instead.
 */

type ApiRequestInit = Omit<RequestInit, 'credentials'>;

export async function apiFetch(path: string, init?: ApiRequestInit): Promise<Response> {
  return fetch(`/api${path}`, {
    ...init,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...init?.headers,
    },
  });
}
