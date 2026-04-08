import type { AccountFlowMode, ControlPlaneAccountDraft, FooterAction } from '../contracts';
import { getCreateSetupPath, getEditSetupPath } from '@/shared/cp/links';
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
import { TOTAL_SETUP_GROUPS } from '../setup-groups';
import { ControlPlaneShell } from '@/shared/cp/components/control-plane-shell';

type AccountReviewScreenProps = {
  mode: AccountFlowMode;
  account: ControlPlaneAccountDraft;
};

export function AccountReviewScreen({ mode, account }: AccountReviewScreenProps) {
  const isEditMode = mode === 'edit';
  const currentPath = isEditMode
    ? 'Accounts > Edit Account > Review & Publish'
    : 'Accounts > Create Account > Review & Publish';

  const footerActions: FooterAction[] = [
    {
      label: 'Back',
      href: isEditMode ? getEditSetupPath(account.key) : getCreateSetupPath(),
      variant: 'ghost',
    },
    { label: 'Save Draft', variant: 'secondary', disabled: true },
    {
      label: isEditMode ? 'Save Changes' : 'Create Account',
      variant: 'primary',
      disabled: true,
    },
  ];

  return (
    <ControlPlaneShell
      currentPath={currentPath}
      pageTitle="Review & Publish"
      pageDescription="Step 3 consolidates the draft identity and setup review progress into the locked final shell for later publish work."
      footerActions={footerActions}
      account={account}
      step={{ stepNumber: 3, stepName: 'Review & Publish' }}
    >
      <section style={sectionGridStyle}>
        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Account summary</h2>
          <div style={infoGridStyle}>
            <div style={infoCardStyle}>
              <p style={labelStyle}>Account name</p>
              <p style={valueStyle}>{account.name}</p>
            </div>
            <div style={infoCardStyle}>
              <p style={labelStyle}>Account key</p>
              <p style={valueStyle}>{account.key}</p>
            </div>
            <div style={infoCardStyle}>
              <p style={labelStyle}>Setup progress</p>
              <p style={valueStyle}>
                {account.setupGroupsReviewed.length} / {TOTAL_SETUP_GROUPS} sections reviewed
              </p>
            </div>
            <div style={infoCardStyle}>
              <p style={labelStyle}>Status</p>
              <p style={valueStyle}>{account.cpStatus}</p>
            </div>
          </div>
        </article>

        <article style={insetPanelStyle}>
          <strong>Phase 1 placeholder boundary</strong>
          <p style={mutedTextStyle}>
            The final action stays disabled because creation and edit persistence are not
            implemented yet. This page only locks the route, shell, summary surface, and correct
            footer action labels.
          </p>
        </article>
      </section>
    </ControlPlaneShell>
  );
}
