/**
 * cp/src/features/accounts/cp-accounts-api.ts
 *
 * WHY:
 * - Server-side API helpers for CP account reads.
 * - Uses cpSsrFetch so Server Components never hardcode backend origins.
 */

import { cpSsrFetch } from '@/shared/cp/ssr-api-client';
import type {
  ControlPlaneAccountDetail,
  ControlPlaneAccountListItem,
  ControlPlaneAccountReview,
} from './contracts';

export async function fetchCpAccountsList(): Promise<ControlPlaneAccountListItem[]> {
  const res = await cpSsrFetch('/cp/accounts');

  if (!res.ok) {
    throw new Error(`Failed to load CP accounts: ${res.status} ${res.statusText}`);
  }

  const data = (await res.json()) as { accounts?: ControlPlaneAccountListItem[] };
  return data.accounts ?? [];
}

export async function fetchCpAccount(
  accountKey: string,
): Promise<ControlPlaneAccountDetail | null> {
  const res = await cpSsrFetch(`/cp/accounts/${encodeURIComponent(accountKey)}`);

  if (res.status === 404) {
    return null;
  }

  if (!res.ok) {
    throw new Error(`Failed to load CP account "${accountKey}": ${res.status} ${res.statusText}`);
  }

  return (await res.json()) as ControlPlaneAccountDetail;
}

export async function fetchCpAccountReview(
  accountKey: string,
): Promise<ControlPlaneAccountReview | null> {
  const res = await cpSsrFetch(`/cp/accounts/${encodeURIComponent(accountKey)}/review`);

  if (res.status === 404) {
    return null;
  }

  if (!res.ok) {
    throw new Error(
      `Failed to load CP account review "${accountKey}": ${res.status} ${res.statusText}`,
    );
  }

  return (await res.json()) as ControlPlaneAccountReview;
}
