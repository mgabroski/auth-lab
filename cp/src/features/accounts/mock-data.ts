import type { ControlPlaneAccountDraft, ControlPlaneAccountListItem } from './contracts';

const CREATE_ACCOUNT_DRAFT: ControlPlaneAccountDraft = {
  id: 'draft-new-account',
  name: 'Northwind Health',
  key: 'northwind-health',
  setupGroupsReviewed: ['access-identity-security', 'account-settings'],
  cpStatus: 'Draft',
};

const EXISTING_ACCOUNTS: ControlPlaneAccountDraft[] = [
  {
    id: 'acct-goodwill-ca',
    name: 'Goodwill CA',
    key: 'goodwill-ca',
    setupGroupsReviewed: [
      'access-identity-security',
      'account-settings',
      'module-settings',
      'integrations-marketplace',
    ],
    cpStatus: 'Active',
  },
  {
    id: 'acct-goodwill-open',
    name: 'Goodwill Open',
    key: 'goodwill-open',
    setupGroupsReviewed: ['access-identity-security', 'module-settings'],
    cpStatus: 'Draft',
  },
];

function toListItem(account: ControlPlaneAccountDraft): ControlPlaneAccountListItem {
  return {
    id: account.id,
    name: account.name,
    key: account.key,
    cpStatus: account.cpStatus,
    setupGroupsReviewed: account.setupGroupsReviewed,
  };
}

export function loadAccountsList(): Promise<ControlPlaneAccountListItem[]> {
  // TODO Phase 2: replace with real API call
  return Promise.resolve(EXISTING_ACCOUNTS.map(toListItem));
}

export function loadCreateAccountDraft(): Promise<ControlPlaneAccountDraft> {
  // TODO Phase 2: replace with real API call
  return Promise.resolve(CREATE_ACCOUNT_DRAFT);
}

export function loadEditableAccount(accountKey: string): Promise<ControlPlaneAccountDraft | null> {
  // TODO Phase 2: replace with real API call
  return Promise.resolve(EXISTING_ACCOUNTS.find((account) => account.key === accountKey) ?? null);
}
