/**
 * cp/src/features/accounts/contracts.ts
 *
 * WHY:
 * - Shared type contracts for the CP accounts feature.
 * - Used by screens, API layer, and page components.
 *
 * PHASE 1 TYPES (preserved):
 * - ControlPlaneAccountDraft — working type used by existing shell components and
 *   screens that use name / key / setupGroupsReviewed field names. These must not
 *   change until those consuming screens are updated in a later phase.
 * - ControlPlaneAccountListItem — slim list-row shape for AccountsListScreen.
 *
 * PHASE 2 TYPES (added):
 * - ControlPlaneAccount — full account shape returned by GET /cp/accounts/:key.
 *   Field names (accountName / accountKey) match the backend JSON directly.
 * - ControlPlaneAccountApiListItem — slim row from GET /cp/accounts backend response.
 * - CreateCpAccountInput — request body for POST /cp/accounts.
 *
 * ADAPTER RULE:
 * - mock-data.ts adapts ControlPlaneAccount → ControlPlaneAccountDraft so existing
 *   screens keep working with real data without requiring a broader field rename.
 *   This adapter is removed when screens are updated to use ControlPlaneAccount
 *   field names directly (later phase cleanup).
 *
 * RULES:
 * - No runtime logic here. Types only.
 * - Must stay aligned with backend cp-accounts.types.ts and response shapes.
 *
 * CP STATUS VOCABULARY (locked):
 * - 'Draft'    — created but not yet published
 * - 'Active'   — published and reachable by tenants
 * - 'Disabled' — published but access is suspended
 */

export type AccountFlowMode = 'create' | 'edit';

export type SetupGroupSlug =
  | 'access-identity-security'
  | 'account-settings'
  | 'module-settings'
  | 'integrations-marketplace';

export type SetupGroupDefinition = {
  slug: SetupGroupSlug;
  title: string;
  shortLabel: string;
  description: string;
};

export type CpStatus = 'Draft' | 'Active' | 'Disabled';

// ─── Phase 1 types ─────────────────────────────────────────────────────────
// Shell components and existing screens depend on these field names.
// Do not rename fields here until the consuming screens are updated.

export type ControlPlaneAccountDraft = {
  id: string;
  name: string;
  key: string;
  setupGroupsReviewed: SetupGroupSlug[];
  cpStatus: CpStatus;
};

export type ControlPlaneAccountListItem = Pick<
  ControlPlaneAccountDraft,
  'id' | 'name' | 'key' | 'cpStatus' | 'setupGroupsReviewed'
>;

// ─── Phase 2 types ─────────────────────────────────────────────────────────
// Use these in new pages and new screens.
// API layer (cp-accounts-api.ts) uses these to match the backend response shape.

/**
 * Full CP account — matches GET /cp/accounts/:accountKey response.
 */
export type ControlPlaneAccount = {
  id: string;
  accountName: string;
  accountKey: string;
  cpStatus: CpStatus;
  cpRevision: number;
  createdAt: string;
  updatedAt: string;
};

/**
 * Slim list row — matches each item in the GET /cp/accounts response body.
 */
export type ControlPlaneAccountApiListItem = {
  id: string;
  accountName: string;
  accountKey: string;
  cpStatus: CpStatus;
  cpRevision: number;
};

/**
 * POST /cp/accounts request body.
 */
export type CreateCpAccountInput = {
  accountName: string;
  accountKey: string;
};

export type StepDefinition = {
  stepNumber: 1 | 2 | 3;
  name: string;
};

export type FooterAction = {
  label: string;
  href?: string;
  variant?: 'ghost' | 'secondary' | 'primary';
  disabled?: boolean;
  /** Client-side click handler. Used when action drives form submission rather than navigation. */
  onClick?: () => void;
};
