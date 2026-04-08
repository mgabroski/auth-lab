import type { AccountFlowMode, ControlPlaneAccountDraft, FooterAction } from '../contracts';
import {
  getCreateBasicInfoPath,
  getCreateReviewPath,
  getCreateSetupGroupPath,
  getEditBasicInfoPath,
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
  valueStyle,
} from '@/shared/cp/styles';
import { TOTAL_SETUP_GROUPS } from '../setup-groups';
import { ControlPlaneShell } from '@/shared/cp/components/control-plane-shell';
import { SetupGroupGrid } from '@/shared/cp/components/setup-group-grid';

type AccountSetupOverviewScreenProps = {
  mode: AccountFlowMode;
  account: ControlPlaneAccountDraft;
};

export function AccountSetupOverviewScreen({ mode, account }: AccountSetupOverviewScreenProps) {
  const isEditMode = mode === 'edit';
  const currentPath = isEditMode
    ? 'Accounts > Edit Account > Account Setup'
    : 'Accounts > Create Account > Account Setup';

  const footerActions: FooterAction[] = [
    {
      label: 'Back',
      href: isEditMode ? getEditBasicInfoPath(account.key) : getCreateBasicInfoPath(),
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
      pageDescription="Step 2 overview shows the four locked setup groups and the reviewed progress count."
      footerActions={footerActions}
      account={account}
      step={{ stepNumber: 2, stepName: 'Account Setup' }}
      showStepProgress
    >
      <section style={sectionGridStyle}>
        <SetupGroupGrid
          account={account}
          getGroupHref={(groupSlug) =>
            isEditMode
              ? getEditSetupGroupPath(account.key, groupSlug)
              : getCreateSetupGroupPath(groupSlug)
          }
        />

        <div style={infoGridStyle}>
          <article style={infoCardStyle}>
            <p style={labelStyle}>Reviewed groups</p>
            <p style={valueStyle}>
              {account.setupGroupsReviewed.length} of {TOTAL_SETUP_GROUPS}
            </p>
          </article>
          <article style={infoCardStyle}>
            <p style={labelStyle}>Status</p>
            <p style={valueStyle}>{account.cpStatus}</p>
          </article>
        </div>

        <article style={insetPanelStyle}>
          <strong>Phase 1 placeholder boundary</strong>
          <p style={mutedTextStyle}>
            Group detail content is static in this phase. Real group persistence, review-state
            updates, and publish gating rules are intentionally deferred.
          </p>
        </article>
      </section>
    </ControlPlaneShell>
  );
}
