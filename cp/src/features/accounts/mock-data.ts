/**
 * cp/src/features/accounts/mock-data.ts
 *
 * CP Phase 2: all functions now call the real backend via cp-accounts-api.ts.
 *
 * WHY this file still exists as a facade:
 * - Page components are wired to these function names. Keeping the same export
 *   surface means zero churn on existing page imports.
 * - The adapter functions below translate the Phase 2 API shapes
 *   (ControlPlaneAccount / ControlPlaneAccountApiListItem) into the Phase 1
 *   screen types (ControlPlaneAccountDraft / ControlPlaneAccountListItem) so
 *   that existing screens continue to compile and render correctly.
 *
 * ADAPTER REMOVAL:
 * - When AccountsListScreen, AccountSetupOverviewScreen, and AccountReviewScreen
 *   are updated to use ControlPlaneAccount field names directly, the adapter
 *   functions here can be replaced with direct pass-through calls.
 *   That is later-phase cleanup, not Phase 2 scope.
 *
 * RULES:
 * - No mock data. No hardcoded placeholder arrays.
 * - All reads go through cp-accounts-api.ts → cpSsrFetch → INTERNAL_API_URL.
 * - Server-side use only (matches existing page component usage pattern).
 */

import type {
  ControlPlaneAccountDraft,
  ControlPlaneAccountListItem,
  SetupGroupSlug,
} from './contracts';
import { fetchCpAccountsList, fetchCpAccount } from './cp-accounts-api';

/**
 * Returns the CP accounts list adapted to the Phase 1 screen shape.
 * setupGroupsReviewed is empty in Phase 2 — group saves are deferred.
 */
export async function loadAccountsList(): Promise<ControlPlaneAccountListItem[]> {
  const apiRows = await fetchCpAccountsList();

  return apiRows.map((row) => ({
    id: row.id,
    name: row.accountName,
    key: row.accountKey,
    cpStatus: row.cpStatus,
    setupGroupsReviewed: [] as SetupGroupSlug[],
  }));
}

/**
 * Returns a single CP account adapted to the Phase 1 screen shape.
 * Returns null if not found.
 * setupGroupsReviewed is empty in Phase 2 — group saves are deferred.
 */
export async function loadEditableAccount(
  accountKey: string,
): Promise<ControlPlaneAccountDraft | null> {
  const account = await fetchCpAccount(accountKey);

  if (!account) return null;

  return {
    id: account.id,
    name: account.accountName,
    key: account.accountKey,
    cpStatus: account.cpStatus,
    // Phase 2: group saves are deferred. No groups are configured yet.
    setupGroupsReviewed: [] as SetupGroupSlug[],
  };
}

/**
 * @deprecated Phase 1 stub — no longer used on the create/basic-info page.
 * The create flow starts with an empty form. There is no pre-existing draft to load.
 * Kept to prevent build errors from any stale import still referencing this export.
 * Remove in Phase 3 cleanup.
 */
export function loadCreateAccountDraft(): Promise<ControlPlaneAccountDraft | null> {
  return Promise.resolve(null);
}
