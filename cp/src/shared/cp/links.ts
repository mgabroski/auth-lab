import type { SetupGroupSlug, StepDefinition } from '@/features/accounts/contracts';

export const CONTROL_PLANE_TITLE = 'Control Plane';

export const CREATE_FLOW_STEPS: StepDefinition[] = [
  { stepNumber: 1, name: 'Basic Account Info' },
  { stepNumber: 2, name: 'Account Setup' },
  { stepNumber: 3, name: 'Review & Publish' },
];

export function getAccountsListPath(): string {
  return '/accounts';
}

export function getCreateFlowEntryPath(): string {
  return getCreateBasicInfoPath();
}

export function getCreateBasicInfoPath(): string {
  return '/accounts/create/basic-info';
}

export function getCreateSetupPath(): string {
  return '/accounts/create/setup';
}

export function getCreateSetupGroupPath(groupSlug: SetupGroupSlug): string {
  return `/accounts/create/setup/${groupSlug}`;
}

export function getCreateReviewPath(): string {
  return '/accounts/create/review';
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

export function getEditReviewPath(accountKey: string): string {
  return `/accounts/${accountKey}/edit/review`;
}
