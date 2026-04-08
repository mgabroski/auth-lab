import type { AccountFlowMode, ControlPlaneAccountDraft, FooterAction } from '../contracts';
import { getAccountsListPath, getCreateSetupPath, getEditSetupPath } from '@/shared/cp/links';
import {
  contentPanelStyle,
  infoCardStyle,
  infoGridStyle,
  insetPanelStyle,
  labelStyle,
  mutedTextStyle,
  sectionGridStyle,
  sectionTitleStyle,
  valueStyle,
} from '@/shared/cp/styles';
import { ControlPlaneShell } from '@/shared/cp/components/control-plane-shell';

type AccountBasicInfoScreenProps = {
  mode: AccountFlowMode;
  account: ControlPlaneAccountDraft;
};

export function AccountBasicInfoScreen({ mode, account }: AccountBasicInfoScreenProps) {
  const isEditMode = mode === 'edit';
  const currentPath = isEditMode
    ? 'Accounts > Edit Account > Basic Account Info'
    : 'Accounts > Create Account > Basic Account Info';

  const continueHref = isEditMode ? getEditSetupPath(account.key) : getCreateSetupPath();

  const footerActions: FooterAction[] = [
    { label: 'Back', href: getAccountsListPath(), variant: 'ghost' },
    { label: 'Save Draft', variant: 'secondary', disabled: true },
    {
      label: 'Continue',
      href: continueHref,
      variant: 'primary',
    },
  ];

  return (
    <ControlPlaneShell
      currentPath={currentPath}
      pageTitle="Basic Account Info"
      pageDescription="Phase 1 renders the Step 1 shell with typed placeholder account identity data and the locked footer action pattern."
      footerActions={footerActions}
      step={{ stepNumber: 1, stepName: 'Basic Account Info' }}
    >
      <section style={sectionGridStyle}>
        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Draft account identity</h2>
          <div style={infoGridStyle}>
            <div style={infoCardStyle}>
              <p style={labelStyle}>Account name</p>
              <p style={valueStyle}>{account.name}</p>
            </div>
            <div style={infoCardStyle}>
              <p style={labelStyle}>Account key</p>
              <p style={valueStyle}>{account.key}</p>
            </div>
          </div>
        </article>

        <article style={insetPanelStyle}>
          <strong>Phase 1 placeholder boundary</strong>
          <p style={mutedTextStyle}>
            This page intentionally stops at the typed display boundary. Form submission, draft
            persistence, validation, and publish flow mutations belong to Phase 2. Account name and
            key are the only identity fields in the locked CP Step 1 model.
          </p>
        </article>
      </section>
    </ControlPlaneShell>
  );
}
