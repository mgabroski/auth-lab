/**
 * cp/src/features/accounts/screens/accounts-list-screen.tsx
 *
 * WHY:
 * - Renders the CP accounts list for operator re-entry and edit routing.
 * - Phase 3 shows real Step 2 progress and keeps edit/re-entry grounded in
 *   saved backend truth.
 */

import Link from 'next/link';
import type { CSSProperties } from 'react';
import type { ControlPlaneAccountListItem, FooterAction } from '../contracts';
import { getCreateFlowEntryPath, getEditReviewPath, getEditSetupPath } from '@/shared/cp/links';
import {
  contentPanelStyle,
  infoCardStyle,
  infoGridStyle,
  insetPanelStyle,
  labelStyle,
  mutedTextStyle,
  sectionGridStyle,
  sectionTitleStyle,
  tableCellStyle,
  tableStyle,
  valueStyle,
} from '@/shared/cp/styles';
import { ControlPlaneShell } from '@/shared/cp/components/control-plane-shell';

const inlineLinkStyle: CSSProperties = {
  color: '#0f172a',
  textDecoration: 'none',
  fontWeight: 700,
};

const actionRowStyle: CSSProperties = {
  display: 'flex',
  gap: '12px',
  flexWrap: 'wrap',
  alignItems: 'center',
};

const tableHeaderCellStyle: CSSProperties = {
  ...tableCellStyle,
  borderTop: 'none',
  fontSize: '12px',
  fontWeight: 700,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  color: '#64748b',
};

const statusBadgeStyle = (status: ControlPlaneAccountListItem['cpStatus']): CSSProperties => {
  const palette =
    status === 'Active'
      ? { backgroundColor: '#dcfce7', color: '#166534' }
      : status === 'Disabled'
        ? { backgroundColor: '#e2e8f0', color: '#334155' }
        : { backgroundColor: '#fef3c7', color: '#92400e' };

  return {
    display: 'inline-flex',
    width: 'fit-content',
    padding: '6px 10px',
    borderRadius: '999px',
    fontSize: '12px',
    fontWeight: 700,
    ...palette,
  };
};

const emptyStateStyle: CSSProperties = {
  padding: '24px',
  borderRadius: '16px',
  border: '1px dashed #cbd5e1',
  backgroundColor: '#f8fafc',
  display: 'grid',
  gap: '10px',
};

function getSetupProgressLabel(account: ControlPlaneAccountListItem): string {
  const { configuredCount, totalCount, requiredConfiguredCount, requiredTotalCount } =
    account.step2Progress;

  if (configuredCount === 0) {
    return 'No groups configured yet';
  }

  if (account.step2Progress.canContinueToReview) {
    return `${configuredCount} of ${totalCount} groups configured — ready for review`;
  }

  return `${requiredConfiguredCount} of ${requiredTotalCount} required groups configured`;
}

export function AccountsListScreen({ accounts }: { accounts: ControlPlaneAccountListItem[] }) {
  const footerActions: FooterAction[] = [
    {
      label: 'Create Account',
      href: getCreateFlowEntryPath(),
      variant: 'primary',
    },
  ];

  const activeCount = accounts.filter((account) => account.cpStatus === 'Active').length;
  const draftCount = accounts.filter((account) => account.cpStatus === 'Draft').length;
  const disabledCount = accounts.filter((account) => account.cpStatus === 'Disabled').length;

  return (
    <ControlPlaneShell
      currentPath="Accounts"
      pageTitle="Accounts"
      pageDescription="Provision and manage tenant accounts from the Control Plane. Step 2 progress now reflects real persisted group saves."
      footerActions={footerActions}
    >
      <section style={sectionGridStyle}>
        <div style={infoGridStyle}>
          <article style={infoCardStyle}>
            <p style={labelStyle}>Total accounts</p>
            <p style={valueStyle}>{accounts.length}</p>
          </article>

          <article style={infoCardStyle}>
            <p style={labelStyle}>Draft</p>
            <p style={valueStyle}>{draftCount}</p>
          </article>

          <article style={infoCardStyle}>
            <p style={labelStyle}>Active</p>
            <p style={valueStyle}>{activeCount}</p>
          </article>

          <article style={infoCardStyle}>
            <p style={labelStyle}>Disabled</p>
            <p style={valueStyle}>{disabledCount}</p>
          </article>
        </div>

        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>All accounts</h2>

          {accounts.length === 0 ? (
            <div style={emptyStateStyle}>
              <p style={valueStyle}>No accounts yet. Create your first account to get started.</p>
              <Link href={getCreateFlowEntryPath()} style={inlineLinkStyle}>
                Create Account →
              </Link>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={tableStyle}>
                <thead>
                  <tr>
                    <th style={tableHeaderCellStyle}>Account Name</th>
                    <th style={tableHeaderCellStyle}>Account Key</th>
                    <th style={tableHeaderCellStyle}>Status</th>
                    <th style={tableHeaderCellStyle}>Setup Progress</th>
                    <th style={tableHeaderCellStyle}>Revision</th>
                    <th style={tableHeaderCellStyle}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {accounts.map((account) => (
                    <tr key={account.id}>
                      <td style={tableCellStyle}>{account.accountName}</td>
                      <td style={tableCellStyle}>{account.accountKey}</td>
                      <td style={tableCellStyle}>
                        <span style={statusBadgeStyle(account.cpStatus)}>{account.cpStatus}</span>
                      </td>
                      <td style={tableCellStyle}>{getSetupProgressLabel(account)}</td>
                      <td style={tableCellStyle}>{account.cpRevision}</td>
                      <td style={tableCellStyle}>
                        <div style={actionRowStyle}>
                          <Link href={getEditSetupPath(account.accountKey)} style={inlineLinkStyle}>
                            Edit Setup
                          </Link>
                          <Link
                            href={getEditReviewPath(account.accountKey)}
                            style={inlineLinkStyle}
                          >
                            Review
                          </Link>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </article>

        <article style={insetPanelStyle}>
          <strong>Current boundary</strong>
          <p style={mutedTextStyle}>
            Phase 3 ships real group persistence and continuation gating. Final publish and status
            toggle actions remain deferred to Review & Publish work.
          </p>
        </article>
      </section>
    </ControlPlaneShell>
  );
}
