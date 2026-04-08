import type { CSSProperties } from 'react';
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
import { SETUP_GROUPS, TOTAL_SETUP_GROUPS } from '../setup-groups';
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

const finalStatusCardStyle = (selected: boolean): CSSProperties => ({
  padding: '16px',
  borderRadius: '16px',
  border: `1px solid ${selected ? '#cbd5e1' : '#e2e8f0'}`,
  backgroundColor: selected ? '#f8fafc' : '#ffffff',
  display: 'grid',
  gap: '8px',
});

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

type AccountReviewScreenProps = {
  mode: AccountFlowMode;
  account: ControlPlaneAccountDraft;
};

export function AccountReviewScreen({ mode, account }: AccountReviewScreenProps) {
  const isEditMode = mode === 'edit';
  const currentPath = isEditMode
    ? 'Accounts > Edit Account > Review & Publish'
    : 'Accounts > Create Account > Review & Publish';

  const reviewedCount = account.setupGroupsReviewed.length;
  const allGroupsReviewed = reviewedCount === TOTAL_SETUP_GROUPS;

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
      pageDescription="Step 3 consolidates the draft identity, setup coverage, and final status direction into the locked Control Plane review shell."
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
              <p style={labelStyle}>Step 2 progress</p>
              <p style={valueStyle}>
                {reviewedCount} of {TOTAL_SETUP_GROUPS} groups reviewed
              </p>
              <p style={mutedTextStyle}>
                {allGroupsReviewed
                  ? 'All four locked setup groups are marked as reviewed in this draft.'
                  : 'This draft is still missing reviewed setup groups before the final publish step can become fully actionable.'}
              </p>
            </div>

            <div style={infoCardStyle}>
              <p style={labelStyle}>Current draft status</p>
              <p style={valueStyle}>{account.cpStatus}</p>
              <p style={mutedTextStyle}>
                Phase 1 keeps final persistence and publish actions disabled while preserving the
                locked review shell.
              </p>
            </div>
          </div>
        </article>

        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Activation Ready checklist</h2>

          <div style={checklistStyle}>
            <div style={checklistRowStyle(Boolean(account.name && account.key))}>
              <span
                style={checklistDotStyle(Boolean(account.name && account.key))}
                aria-hidden="true"
              />
              <span>Basic Account Info exists: account name and account key are present.</span>
            </div>

            <div style={checklistRowStyle(allGroupsReviewed)}>
              <span style={checklistDotStyle(allGroupsReviewed)} aria-hidden="true" />
              <span>All four locked Step 2 setup groups are reviewed.</span>
            </div>

            <div
              style={checklistRowStyle(
                account.setupGroupsReviewed.includes('access-identity-security'),
              )}
            >
              <span
                style={checklistDotStyle(
                  account.setupGroupsReviewed.includes('access-identity-security'),
                )}
                aria-hidden="true"
              />
              <span>Access, Identity &amp; Security has been reviewed in the current draft.</span>
            </div>

            <div style={checklistRowStyle(account.setupGroupsReviewed.includes('module-settings'))}>
              <span
                style={checklistDotStyle(account.setupGroupsReviewed.includes('module-settings'))}
                aria-hidden="true"
              />
              <span>Module Settings has been reviewed in the current draft.</span>
            </div>
          </div>

          <p style={mutedTextStyle}>
            This checklist matches the locked Phase 1 shell direction only. Real Activation Ready
            enforcement is intentionally deferred until backend persistence and validation arrive in
            later phases.
          </p>
        </article>

        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Step 2 group coverage</h2>

          <div style={infoGridStyle}>
            {SETUP_GROUPS.map((group) => {
              const reviewed = account.setupGroupsReviewed.includes(group.slug);

              return (
                <div key={group.slug} style={infoCardStyle}>
                  <p style={labelStyle}>{group.shortLabel}</p>
                  <p style={valueStyle}>{reviewed ? 'Reviewed in draft' : 'Still needs review'}</p>
                  <p style={mutedTextStyle}>{group.description}</p>
                </div>
              );
            })}
          </div>
        </article>

        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Final status direction</h2>

          <div style={finalStatusGridStyle}>
            <div style={finalStatusCardStyle(account.cpStatus === 'Draft')}>
              {account.cpStatus === 'Draft' ? (
                <span style={selectedBadgeStyle}>Current selection</span>
              ) : null}
              <p style={labelStyle}>Draft</p>
              <p style={valueStyle}>Keep the account as a work in progress.</p>
              <p style={mutedTextStyle}>
                Used when setup review is still incomplete or the operator is not ready to finalize
                the account state.
              </p>
            </div>

            <div style={finalStatusCardStyle(account.cpStatus === 'Active')}>
              {account.cpStatus === 'Active' ? (
                <span style={selectedBadgeStyle}>Current selection</span>
              ) : null}
              <p style={labelStyle}>Active</p>
              <p style={valueStyle}>Ready for a later real publish flow.</p>
              <p style={mutedTextStyle}>
                In later phases, this option will require real Activation Ready enforcement and
                persistence.
              </p>
            </div>

            <div style={finalStatusCardStyle(account.cpStatus === 'Disabled')}>
              {account.cpStatus === 'Disabled' ? (
                <span style={selectedBadgeStyle}>Current selection</span>
              ) : null}
              <p style={labelStyle}>Disabled</p>
              <p style={valueStyle}>Account exists but remains unusable.</p>
              <p style={mutedTextStyle}>
                This keeps the account out of active use while preserving its Control Plane draft
                decisions.
              </p>
            </div>
          </div>
        </article>

        <article style={insetPanelStyle}>
          <strong>Phase 1 placeholder boundary</strong>
          <ul style={summaryListStyle}>
            <li>
              Final create and save actions stay disabled because persistence is not implemented
              yet.
            </li>
            <li>Activation Ready is shown as a shell checklist only in this phase.</li>
            <li>
              Real publish validation, backend save flows, and cpRevision updates are later-phase
              work.
            </li>
          </ul>
        </article>
      </section>
    </ControlPlaneShell>
  );
}
