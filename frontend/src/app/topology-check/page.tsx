/**
 * frontend/src/app/topology-check/page.tsx
 *
 * WHY:
 * - Preserves the old topology smoke page on a dedicated non-root route.
 * - Still proves the SSR → backend path works using `/auth/config`.
 *
 * RULES:
 * - Server Component only — no 'use client'.
 * - Uses ssrFetch (INTERNAL_API_URL, not /api/*).
 */

import { ssrFetch } from '@/shared/ssr-api-client';
import type { ConfigResponse } from '@/shared/auth/contracts';

export const dynamic = 'force-dynamic';

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
    <main>
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
    </main>
  );
}
