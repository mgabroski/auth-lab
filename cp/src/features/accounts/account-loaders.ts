/**
 * cp/src/features/accounts/account-loaders.ts
 *
 * WHY:
 * - Thin server-side account loader facade for CP pages.
 * - Keeps page imports stable and centralizes route-intent checks close to the
 *   runtime-backed loaders.
 * - Create-flow loaders must stay honest: they may only resolve Draft accounts.
 */

import type { ControlPlaneAccountDetail } from './contracts';
import { fetchCpAccount, fetchCpAccountReview, fetchCpAccountsList } from './cp-accounts-api';

function asDraftAccount(
  account: ControlPlaneAccountDetail | null,
): ControlPlaneAccountDetail | null {
  if (!account || account.cpStatus !== 'Draft') {
    return null;
  }

  return account;
}

export const loadAccountsList = fetchCpAccountsList;
export const loadEditableAccount = fetchCpAccount;
export async function loadDraftAccountByKey(
  accountKey: string,
): Promise<ControlPlaneAccountDetail | null> {
  const account = await fetchCpAccount(accountKey);
  return asDraftAccount(account);
}
export const loadAccountReviewByKey = fetchCpAccountReview;
