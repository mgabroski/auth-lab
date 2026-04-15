import type { CSSProperties } from 'react';
import type { AccountFlowMode, ControlPlaneAccountDetail, FooterAction } from '../contracts';
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
import { ControlPlaneShell } from '@/shared/cp/components/control-plane-shell';

const checklistStyle: CSSProperties = {
  display: 'grid',
  gap: '10px',
};

const checklistRowStyle = (complete: boolean): CSSProperties => ({
  display: 'flex',
  alignItems: 'center',
  gap: '10px',
  color: complete ? '#166534' : '#92400e',
  fontWeight: 600,
  fontSize: '14px',
});

const checklistDotStyle = (complete: boolean): CSSProperties => ({
  width: '10px',
  height: '10px',
  borderRadius: '999px',
  backgroundColor: complete ? '#22c55e' : '#f59e0b',
  flexShrink: 0,
});

const summaryListStyle: CSSProperties = {
  margin: 0,
  paddingLeft: '18px',
  display: 'grid',
  gap: '8px',
  color: '#334155',
  fontSize: '14px',
  lineHeight: 1.6,
};

const finalStatusGridStyle: CSSProperties = {
  display: 'grid',
  gap: '12px',
  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
};

const finalStatusCardStyle: CSSProperties = {
  padding: '16px',
  borderRadius: '16px',
  border: '1px solid #e2e8f0',
  backgroundColor: '#ffffff',
  display: 'grid',
  gap: '8px',
};

const selectedBadgeStyle: CSSProperties = {
  display: 'inline-flex',
  width: 'fit-content',
  padding: '6px 10px',
  borderRadius: '999px',
  backgroundColor: '#e2e8f0',
  color: '#0f172a',
  fontSize: '12px',
  fontWeight: 700,
};

export function AccountReviewScreen({
  mode,
  account,
}: {
  mode: AccountFlowMode;
  account: ControlPlaneAccountDetail;
}) {
  const isEditMode = mode === 'edit';
  const currentPath = isEditMode
    ? 'Accounts > Edit Account > Review & Publish'
    : 'Accounts > Create Account > Review & Publish';

  const footerActions: FooterAction[] = [
    {
      label: 'Back',
      href: isEditMode
        ? getEditSetupPath(account.accountKey)
        : getCreateSetupPath(account.accountKey),
      variant: 'ghost',
    },
    {
      label: 'Save Draft',
      variant: 'secondary',
      disabled: true,
    },
    {
      label: isEditMode ? 'Save Changes' : 'Create Account',
      variant: 'primary',
      disabled: true,
    },
  ];

  const googleSsoAllowed = account.integrations.integrations.find(
    (integration) => integration.integrationKey === 'integration.sso.google',
  )?.isAllowed;
  const microsoftSsoAllowed = account.integrations.integrations.find(
    (integration) => integration.integrationKey === 'integration.sso.microsoft',
  )?.isAllowed;
  const hasAtLeastOneLoginMethod = Object.values(account.access.loginMethods).some(Boolean);
  const hasBrokenSsoDependency =
    (account.access.loginMethods.google && !googleSsoAllowed) ||
    (account.access.loginMethods.microsoft && !microsoftSsoAllowed);

  const activationChecks = [
    {
      label: 'Basic Account Info exists',
      complete: Boolean(account.accountName && account.accountKey),
    },
    {
      label: 'Access, Identity & Security configured',
      complete: account.access.configured,
    },
    {
      label: 'Account Settings configured',
      complete: account.accountSettings.configured,
    },
    {
      label: 'Module Settings configured',
      complete: account.moduleSettings.configured,
    },
    {
      label: 'At least one login method is selected',
      complete: hasAtLeastOneLoginMethod,
    },
    {
      label: 'No broken SSO dependency state exists',
      complete: !hasBrokenSsoDependency,
    },
  ];

  return (
    <ControlPlaneShell
      currentPath={currentPath}
      pageTitle="Review & Publish"
      pageDescription="Step 3 now reflects real Step 2 save state, but final publish and status mutation remain intentionally deferred until the next Control Plane phase."
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
              <p style={valueStyle}>{account.accountName}</p>
            </div>

            <div style={infoCardStyle}>
              <p style={labelStyle}>Account key</p>
              <p style={valueStyle}>{account.accountKey}</p>
            </div>

            <div style={infoCardStyle}>
              <p style={labelStyle}>Current status</p>
              <p style={valueStyle}>{account.cpStatus}</p>
            </div>

            <div style={infoCardStyle}>
              <p style={labelStyle}>Current revision</p>
              <p style={valueStyle}>{account.cpRevision}</p>
            </div>
          </div>
        </article>

        <article style={insetPanelStyle}>
          <h2 style={sectionTitleStyle}>Activation Ready pre-check</h2>
          <div style={checklistStyle}>
            {activationChecks.map((item) => (
              <div key={item.label} style={checklistRowStyle(item.complete)}>
                <span style={checklistDotStyle(item.complete)} aria-hidden="true" />
                <span>{item.label}</span>
              </div>
            ))}
          </div>
        </article>

        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Step 2 summary</h2>
          <ul style={summaryListStyle}>
            {account.step2Progress.groups.map((group) => (
              <li key={group.slug}>
                {group.title}: {group.configured ? 'Configured' : 'Not configured yet'}
                {group.isRequired ? ' (required)' : ' (optional)'}
              </li>
            ))}
          </ul>
        </article>

        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Final status</h2>
          <div style={finalStatusGridStyle}>
            <div style={finalStatusCardStyle}>
              <span style={selectedBadgeStyle}>Active</span>
              <p style={mutedTextStyle}>
                Final Active publish is a later-phase backend mutation. This review step currently
                shows whether the required setup gate is satisfied.
              </p>
            </div>
            <div style={finalStatusCardStyle}>
              <span style={selectedBadgeStyle}>Disabled</span>
              <p style={mutedTextStyle}>
                Disabled selection and save wiring are intentionally deferred with publish/status
                workflows.
              </p>
            </div>
          </div>
        </article>
      </section>
    </ControlPlaneShell>
  );
}
