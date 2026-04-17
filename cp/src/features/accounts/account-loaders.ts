/**
 * cp/src/features/accounts/account-loaders.ts
 *
 * WHY:
 * - Thin server-side account loader facade for CP pages.
 * - Keeps page imports stable and centralizes the runtime-backed loader names.
 * - No mock data lives here.
 */

import { fetchCpAccount, fetchCpAccountReview, fetchCpAccountsList } from './cp-accounts-api';

export const loadAccountsList = fetchCpAccountsList;
export const loadEditableAccount = fetchCpAccount;
export const loadDraftAccountByKey = fetchCpAccount;
export const loadAccountReviewByKey = fetchCpAccountReview;
