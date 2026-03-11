/**
 * frontend/src/app/page.tsx
 *
 * WHY:
 * - Topology smoke test page. Proves the full SSR → Backend path works.
 * - Also proves the frontend can resolve tenants via subdomain.
 * - This page will be replaced by the real login/home routing once
 *   the auth screens are built. Until then it serves as a living
 *   topology health check.
 *
 * RULES:
 * - Server Component only — no 'use client'.
 * - Uses ssrFetch (INTERNAL_API_URL, not /api/*) — never apiFetch here.
 * - ConfigResponse type must match auth.types.ts on the backend.
 */

import { ssrFetch } from '@/shared/ssr-api-client';

/**
 * Matches backend ConfigResponse from auth.types.ts.
 * Keep in sync. Future: generate from OpenAPI spec.
 */
type ConfigResponse = {
  tenant: {
    name: string;
    isActive: boolean;
    publicSignupEnabled: boolean;
    allowedSso: ('google' | 'microsoft')[];
  };
};

export default async function TopologyCheckPage() {
  let config: ConfigResponse | null = null;
  let configError: string | null = null;

  try {
    const res = await ssrFetch('/auth/config');
    if (res.ok) {
      config = (await res.json()) as ConfigResponse;
    } else {
      configError = `HTTP ${res.status}`;
    }
  } catch (err) {
    configError = err instanceof Error ? err.message : 'fetch failed';
  }

  return (
    <div>
      <h1>Hubins — Topology Check</h1>

      <h2>Proxy → Frontend</h2>
      <p>✅ Next.js App Router is running</p>

      <h2>SSR → Backend (/auth/config)</h2>
      {configError ? (
        <p>❌ Error: {configError}</p>
      ) : config ? (
        <pre>{JSON.stringify(config, null, 2)}</pre>
      ) : (
        <p>❌ No response</p>
      )}
    </div>
  );
}
