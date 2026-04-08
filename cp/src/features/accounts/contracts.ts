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

export type ControlPlaneAccountDraft = {
  id: string;
  name: string;
  key: string;
  setupGroupsReviewed: SetupGroupSlug[];
  cpStatus: 'Draft' | 'Active' | 'Disabled';
};

export type ControlPlaneAccountListItem = Pick<
  ControlPlaneAccountDraft,
  'id' | 'name' | 'key' | 'cpStatus' | 'setupGroupsReviewed'
>;

export type StepDefinition = {
  stepNumber: 1 | 2 | 3;
  name: string;
};

export type FooterAction = {
  label: string;
  href?: string;
  variant?: 'ghost' | 'secondary' | 'primary';
  disabled?: boolean;
};
