import type { SetupGroupSlug, StepDefinition } from '@/features/accounts/contracts';

export const CONTROL_PLANE_TITLE = 'Control Plane';

export const CREATE_FLOW_STEPS: StepDefinition[] = [
  { stepNumber: 1, name: 'Basic Account Info' },
  { stepNumber: 2, name: 'Account Setup' },
  { stepNumber: 3, name: 'Review & Publish' },
];

function withAccountKey(basePath: string, accountKey?: string): string {
  return accountKey ? `${basePath}?accountKey=${encodeURIComponent(accountKey)}` : basePath;
}

// WHY:
// - Create flow routes do not own the account key in the path yet, so they carry it
//   as a query param while the draft moves through Step 2 and review.
// - Edit flow routes are re-entry routes for an existing published/draft account and
//   therefore own the account key as a stable route segment.

export function getAccountsListPath(): string {
  return '/accounts';
}

export function getCreateFlowEntryPath(): string {
  return getCreateBasicInfoPath();
}

export function getCreateBasicInfoPath(): string {
  return '/accounts/create/basic-info';
}

export function getCreateSetupPath(accountKey?: string): string {
  return withAccountKey('/accounts/create/setup', accountKey);
}

export function getCreateSetupGroupPath(groupSlug: SetupGroupSlug, accountKey?: string): string {
  return withAccountKey(`/accounts/create/setup/${groupSlug}`, accountKey);
}

export function getCreatePersonalSetupPath(accountKey?: string): string {
  return withAccountKey('/accounts/create/setup/module-settings/personal', accountKey);
}

export function getCreateReviewPath(accountKey?: string): string {
  return withAccountKey('/accounts/create/review', accountKey);
}

export function getEditFlowEntryPath(accountKey: string): string {
  return getEditSetupPath(accountKey);
}

export function getEditSetupPath(accountKey: string): string {
  return `/accounts/${accountKey}/edit/setup`;
}

export function getEditSetupGroupPath(accountKey: string, groupSlug: SetupGroupSlug): string {
  return `/accounts/${accountKey}/edit/setup/${groupSlug}`;
}

export function getEditPersonalSetupPath(accountKey: string): string {
  return `/accounts/${accountKey}/edit/setup/module-settings/personal`;
}

export function getEditReviewPath(accountKey: string): string {
  return `/accounts/${accountKey}/edit/review`;
}
