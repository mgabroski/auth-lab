/**
 * cp/src/features/accounts/cp-accounts-api.ts
 *
 * WHY:
 * - Centralises all CP accounts API calls for use in Server Components.
 * - Uses cpSsrFetch (INTERNAL_API_URL path) for server-side reads.
 * - Returns typed Phase 2 domain objects matching the backend JSON shapes.
 * - Client-side mutations (POST create) are made inline in the form component
 *   via the /api/* proxy route — not through this file.
 *
 * RULES:
 * - Server-side use only (Server Components, Route Handlers).
 * - Never import in Client Components.
 * - Throws on unexpected HTTP failures so the page boundary can handle it.
 * - Returns null on 404 — callers decide whether to notFound() or handle gracefully.
 *
 * RESPONSE CONTRACT (backend):
 * - GET /cp/accounts         → { accounts: ControlPlaneAccountApiListItem[] }
 * - GET /cp/accounts/:key    → ControlPlaneAccount (full object)
 */

import { cpSsrFetch } from '@/shared/cp/ssr-api-client';
import type { ControlPlaneAccount, ControlPlaneAccountApiListItem } from './contracts';

/**
 * Fetches all CP accounts from GET /cp/accounts.
 * Throws on non-OK responses. Returns [] if the accounts array is missing.
 */
export async function fetchCpAccountsList(): Promise<ControlPlaneAccountApiListItem[]> {
  const res = await cpSsrFetch('/cp/accounts');

  if (!res.ok) {
    throw new Error(`Failed to load CP accounts: ${res.status} ${res.statusText}`);
  }

  const data = (await res.json()) as { accounts?: ControlPlaneAccountApiListItem[] };
  return data.accounts ?? [];
}

/**
 * Fetches a single CP account by its accountKey from GET /cp/accounts/:accountKey.
 * Returns null on 404. Throws on all other non-OK responses.
 */
export async function fetchCpAccount(accountKey: string): Promise<ControlPlaneAccount | null> {
  const res = await cpSsrFetch(`/cp/accounts/${encodeURIComponent(accountKey)}`);

  if (res.status === 404) {
    return null;
  }

  if (!res.ok) {
    throw new Error(`Failed to load CP account "${accountKey}": ${res.status} ${res.statusText}`);
  }

  return res.json() as Promise<ControlPlaneAccount>;
}
