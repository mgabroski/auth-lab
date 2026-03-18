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
 *
 * WHY Content-Type is conditional:
 * - Fastify rejects requests where Content-Type is 'application/json' but the
 *   body is empty ("Body cannot be empty when content-type is set to
 *   'application/json'"). This affects parameterless POSTs like setupMfa()
 *   and logout() which send no body.
 * - Setting Content-Type only when a body is present matches HTTP semantics:
 *   Content-Type describes the body format, so it should only be set when
 *   there is a body to describe.
 */

type ApiRequestInit = Omit<RequestInit, 'credentials'>;

export async function apiFetch(path: string, init?: ApiRequestInit): Promise<Response> {
  const hasBody = init?.body !== undefined && init.body !== null;

  return fetch(`/api${path}`, {
    ...init,
    credentials: 'include',
    headers: {
      ...(hasBody ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  });
}
