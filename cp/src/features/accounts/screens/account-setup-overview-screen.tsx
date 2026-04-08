import type { CSSProperties } from 'react';
import type { AccountFlowMode, ControlPlaneAccountDraft, FooterAction } from '../contracts';
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
import { SETUP_GROUPS, TOTAL_SETUP_GROUPS } from '../setup-groups';
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
  account: ControlPlaneAccountDraft;
};

export function AccountSetupOverviewScreen({ mode, account }: AccountSetupOverviewScreenProps) {
  const isEditMode = mode === 'edit';
  const currentPath = isEditMode
    ? 'Accounts > Edit Account > Account Setup'
    : 'Accounts > Create Account > Account Setup';

  const reviewedCount = account.setupGroupsReviewed.length;
  const remainingCount = TOTAL_SETUP_GROUPS - reviewedCount;
  const allGroupsReviewed = reviewedCount === TOTAL_SETUP_GROUPS;

  const nextRecommendedGroup =
    SETUP_GROUPS.find((group) => !account.setupGroupsReviewed.includes(group.slug)) ?? null;

  const footerActions: FooterAction[] = [
    {
      label: 'Back',
      href: isEditMode ? getAccountsListPath() : getCreateBasicInfoPath(),
      variant: 'ghost',
    },
    { label: 'Save Draft', variant: 'secondary', disabled: true },
    {
      label: 'Continue',
      href: isEditMode ? getEditReviewPath(account.key) : getCreateReviewPath(),
      variant: 'primary',
    },
  ];

  return (
    <ControlPlaneShell
      currentPath={currentPath}
      pageTitle="Account Setup"
      pageDescription="Review and save the four locked Control Plane setup groups before continuing to the review and publish step."
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
              {reviewedCount} of {TOTAL_SETUP_GROUPS} groups reviewed
            </p>
            <p style={mutedTextStyle}>
              {allGroupsReviewed
                ? 'All four locked setup groups are reviewed in this draft.'
                : `${remainingCount} group${remainingCount === 1 ? '' : 's'} still need review before Step 2 is fully complete.`}
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
                : 'All setup groups are reviewed. You can continue to the final review step.'}
            </p>
          </article>

          <article style={infoCardStyle}>
            <p style={labelStyle}>Draft status</p>
            <p style={valueStyle}>{account.cpStatus}</p>
            <p style={mutedTextStyle}>
              Phase 1 uses typed placeholder data only. Real persistence and publish rules are wired
              in later phases.
            </p>
          </article>
        </div>

        <article style={insetPanelStyle}>
          <h2 style={sectionTitleStyle}>Locked Step 2 checklist</h2>
          <div style={sectionGridStyle}>
            {SETUP_GROUPS.map((group) => {
              const isComplete = account.setupGroupsReviewed.includes(group.slug);

              return (
                <div key={group.slug} style={checklistItemStyle(isComplete)}>
                  <span style={checklistDotStyle(isComplete)} aria-hidden="true" />
                  <span>{group.title}</span>
                </div>
              );
            })}
          </div>
        </article>

        <SetupGroupGrid
          account={account}
          getGroupHref={(groupSlug) =>
            isEditMode
              ? getEditSetupGroupPath(account.key, groupSlug)
              : getCreateSetupGroupPath(groupSlug)
          }
        />

        <article style={insetPanelStyle}>
          <h2 style={sectionTitleStyle}>Phase 1 placeholder boundary</h2>
          <ul style={summaryListStyle}>
            <li>Group detail pages are intentionally static in this phase.</li>
            <li>Reviewed state comes from typed placeholder draft data only.</li>
            <li>
              Real save persistence, activation-ready enforcement, and publish wiring are deferred
              to the next implementation phases.
            </li>
          </ul>
        </article>
      </section>
    </ControlPlaneShell>
  );
}
