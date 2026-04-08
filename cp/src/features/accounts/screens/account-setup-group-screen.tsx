import type {
  AccountFlowMode,
  ControlPlaneAccountDraft,
  FooterAction,
  SetupGroupDefinition,
} from '../contracts';
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

type AccountSetupGroupScreenProps = {
  mode: AccountFlowMode;
  account: ControlPlaneAccountDraft;
  group: SetupGroupDefinition;
};

export function AccountSetupGroupScreen({ mode, account, group }: AccountSetupGroupScreenProps) {
  const isEditMode = mode === 'edit';
  const setupOverviewPath = isEditMode ? getEditSetupPath(account.key) : getCreateSetupPath();
  const currentPath = isEditMode
    ? `Accounts > Edit Account > Account Setup > ${group.title}`
    : `Accounts > Create Account > Account Setup > ${group.title}`;
  const reviewed = account.setupGroupsReviewed.includes(group.slug);

  const footerActions: FooterAction[] = [
    { label: 'Back', href: setupOverviewPath, variant: 'ghost' },
    { label: 'Save', variant: 'secondary', disabled: true },
    { label: 'Save & Close', href: setupOverviewPath, variant: 'primary' },
  ];

  return (
    <ControlPlaneShell
      currentPath={currentPath}
      pageTitle={group.title}
      pageDescription="Phase 1 creates the exact group-detail route surface and shared footer action pattern without adding backend persistence."
      footerActions={footerActions}
      account={account}
      step={{ stepNumber: 2, stepName: 'Account Setup' }}
      showStepProgress
    >
      <section style={sectionGridStyle}>
        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Group detail placeholder</h2>
          <div style={infoGridStyle}>
            <div style={infoCardStyle}>
              <p style={labelStyle}>Group</p>
              <p style={valueStyle}>{group.title}</p>
            </div>
            <div style={infoCardStyle}>
              <p style={labelStyle}>Current status</p>
              <p style={valueStyle}>{reviewed ? 'Reviewed' : 'Needs review'}</p>
            </div>
          </div>
          <p style={mutedTextStyle}>{group.description}</p>
        </article>

        <article style={insetPanelStyle}>
          <strong>Locked Phase 1 boundary</strong>
          <p style={mutedTextStyle}>
            This route proves the shell, breadcrumb, account context bar, and group-specific
            navigation. Real section forms, validation, and cascade behavior belong to later phases.
          </p>
        </article>
      </section>
    </ControlPlaneShell>
  );
}
