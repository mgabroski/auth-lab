/**
 * cp/src/features/accounts/mock-data.ts
 *
 * WHY:
 * - Retained as a thin data-loader facade so existing page imports can stay stable.
 * - No mock data remains in this file.
 */

import { fetchCpAccount, fetchCpAccountReview, fetchCpAccountsList } from './cp-accounts-api';

export const loadAccountsList = fetchCpAccountsList;
export const loadEditableAccount = fetchCpAccount;
export const loadDraftAccountByKey = fetchCpAccount;
export const loadAccountReviewByKey = fetchCpAccountReview;
