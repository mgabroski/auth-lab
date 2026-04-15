import type { CSSProperties } from 'react';
import type { AccountFlowMode, ControlPlaneAccountDetail, FooterAction } from '../contracts';
import {
  getAccountsListPath,
  getCreateBasicInfoPath,
  getCreateReviewPath,
  getCreateSetupGroupPath,
  getEditReviewPath,
  getEditSetupGroupPath,
} from '@/shared/cp/links';
import {
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
import { SetupGroupGrid } from '@/shared/cp/components/setup-group-grid';

const summaryListStyle: CSSProperties = {
  margin: 0,
  paddingLeft: '18px',
  display: 'grid',
  gap: '8px',
  color: '#334155',
  fontSize: '14px',
  lineHeight: 1.6,
};

const checklistItemStyle = (isComplete: boolean): CSSProperties => ({
  display: 'flex',
  alignItems: 'center',
  gap: '10px',
  color: isComplete ? '#166534' : '#92400e',
  fontWeight: 600,
});

const checklistDotStyle = (isComplete: boolean): CSSProperties => ({
  width: '10px',
  height: '10px',
  borderRadius: '999px',
  backgroundColor: isComplete ? '#22c55e' : '#f59e0b',
  flexShrink: 0,
});

type AccountSetupOverviewScreenProps = {
  mode: AccountFlowMode;
  account: ControlPlaneAccountDetail;
};

export function AccountSetupOverviewScreen({ mode, account }: AccountSetupOverviewScreenProps) {
  const isEditMode = mode === 'edit';
  const currentPath = isEditMode
    ? 'Accounts > Edit Account > Account Setup'
    : 'Accounts > Create Account > Account Setup';

  const { step2Progress } = account;
  const remainingCount = step2Progress.totalCount - step2Progress.configuredCount;
  const nextRecommendedGroup = step2Progress.groups.find((group) => !group.configured) ?? null;

  const reviewPath = isEditMode
    ? getEditReviewPath(account.accountKey)
    : getCreateReviewPath(account.accountKey);

  const footerActions: FooterAction[] = [
    {
      label: 'Back',
      href: isEditMode ? getAccountsListPath() : getCreateBasicInfoPath(),
      variant: 'ghost',
    },
    {
      label: 'Save Draft',
      variant: 'secondary',
      disabled: true,
    },
    {
      label: 'Continue →',
      href: step2Progress.canContinueToReview ? reviewPath : undefined,
      variant: 'primary',
      disabled: !step2Progress.canContinueToReview,
    },
  ];

  return (
    <ControlPlaneShell
      currentPath={currentPath}
      pageTitle="Account Setup"
      pageDescription="Save the four locked Control Plane setup groups. Required groups must be configured before Review & Publish is unlocked."
      footerActions={footerActions}
      account={account}
      step={{ stepNumber: 2, stepName: 'Account Setup' }}
      showStepProgress
    >
      <section style={sectionGridStyle}>
        <div style={infoGridStyle}>
          <article style={infoCardStyle}>
            <p style={labelStyle}>Step 2 progress</p>
            <p style={valueStyle}>
              {step2Progress.configuredCount} of {step2Progress.totalCount} groups configured
            </p>
            <p style={mutedTextStyle}>
              {remainingCount === 0
                ? 'All setup groups are saved. Required-group gating is now satisfied.'
                : `${remainingCount} group${remainingCount === 1 ? '' : 's'} still need attention before Step 2 is fully complete.`}
            </p>
          </article>

          <article style={infoCardStyle}>
            <p style={labelStyle}>Next recommended action</p>
            <p style={valueStyle}>
              {nextRecommendedGroup ? nextRecommendedGroup.title : 'Continue to Review & Publish'}
            </p>
            <p style={mutedTextStyle}>
              {nextRecommendedGroup
                ? 'Open the next incomplete setup group and save its decisions.'
                : 'All required groups are configured. Review is now available.'}
            </p>
          </article>

          <article style={infoCardStyle}>
            <p style={labelStyle}>Draft status</p>
            <p style={valueStyle}>{account.cpStatus}</p>
            <p style={mutedTextStyle}>
              Current revision: {account.cpRevision}. Step 2 saves now persist real CP allowance
              truth and revision changes when meaningful mutations occur.
            </p>
          </article>
        </div>

        <article style={insetPanelStyle}>
          <h2 style={sectionTitleStyle}>Required-group continuation gate</h2>
          <div style={sectionGridStyle}>
            {step2Progress.groups.map((group) => (
              <div key={group.slug} style={checklistItemStyle(group.configured)}>
                <span style={checklistDotStyle(group.configured)} aria-hidden="true" />
                <span>
                  {group.title}
                  {group.isRequired ? ' — required' : ' — optional'}
                </span>
              </div>
            ))}
          </div>
        </article>

        <SetupGroupGrid
          progress={step2Progress}
          getGroupHref={(groupSlug) =>
            isEditMode
              ? getEditSetupGroupPath(account.accountKey, groupSlug)
              : getCreateSetupGroupPath(groupSlug, account.accountKey)
          }
        />

        <article style={insetPanelStyle}>
          <h2 style={sectionTitleStyle}>What counts as configured now</h2>
          <ul style={summaryListStyle}>
            <li>Access, Identity & Security is configured only after an explicit save.</li>
            <li>Account Settings is configured by any explicit allow/deny save.</li>
            <li>
              Module Settings requires a saved module decision, and if Personal is enabled the
              Personal sub-page must also be explicitly saved.
            </li>
            <li>
              Integrations & Marketplace is optional, but an explicit save is enough even when no
              integrations are enabled.
            </li>
          </ul>
        </article>
      </section>
    </ControlPlaneShell>
  );
}
