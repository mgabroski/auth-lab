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
import { TOTAL_SETUP_GROUPS } from '../setup-groups';

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

type AccountsListScreenProps = {
  accounts: ControlPlaneAccountListItem[];
};

function getReviewedSummary(account: ControlPlaneAccountListItem): string {
  const reviewedCount = account.setupGroupsReviewed.length;

  if (reviewedCount === TOTAL_SETUP_GROUPS) {
    return 'All four setup groups reviewed';
  }

  if (reviewedCount === 0) {
    return 'No setup groups reviewed yet';
  }

  return `${reviewedCount} of ${TOTAL_SETUP_GROUPS} setup groups reviewed`;
}

export function AccountsListScreen({ accounts }: AccountsListScreenProps) {
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
      pageDescription="Minimal Phase 1 Control Plane list view for operator re-entry, edit routing, and review routing."
      footerActions={footerActions}
    >
      <section style={sectionGridStyle}>
        <div style={infoGridStyle}>
          <article style={infoCardStyle}>
            <p style={labelStyle}>Total accounts</p>
            <p style={valueStyle}>{accounts.length}</p>
            <p style={mutedTextStyle}>
              Typed placeholder rows available for Control Plane routing review.
            </p>
          </article>

          <article style={infoCardStyle}>
            <p style={labelStyle}>Draft accounts</p>
            <p style={valueStyle}>{draftCount}</p>
            <p style={mutedTextStyle}>
              Draft is the expected placeholder state while real persistence is still deferred.
            </p>
          </article>

          <article style={infoCardStyle}>
            <p style={labelStyle}>Active accounts</p>
            <p style={valueStyle}>{activeCount}</p>
            <p style={mutedTextStyle}>
              Active appears in the placeholder data only. Real publish enforcement lands later.
            </p>
          </article>

          <article style={infoCardStyle}>
            <p style={labelStyle}>Disabled accounts</p>
            <p style={valueStyle}>{disabledCount}</p>
            <p style={mutedTextStyle}>
              Disabled remains part of the locked CP status vocabulary in this phase.
            </p>
          </article>
        </div>

        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Existing accounts</h2>

          {accounts.length === 0 ? (
            <div style={emptyStateStyle}>
              <p style={valueStyle}>No accounts yet. Create your first account to get started.</p>
              <p style={mutedTextStyle}>
                The Phase 1 accounts list exists so QA and engineering can re-enter saved
                placeholder drafts and review routing behavior without database work.
              </p>
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
                    <th style={tableHeaderCellStyle}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {accounts.map((account) => (
                    <tr key={account.id}>
                      <td style={tableCellStyle}>{account.name}</td>
                      <td style={tableCellStyle}>{account.key}</td>
                      <td style={tableCellStyle}>
                        <span style={statusBadgeStyle(account.cpStatus)}>{account.cpStatus}</span>
                      </td>
                      <td style={tableCellStyle}>{getReviewedSummary(account)}</td>
                      <td style={tableCellStyle}>
                        <div style={actionRowStyle}>
                          <Link href={getEditSetupPath(account.key)} style={inlineLinkStyle}>
                            Edit Setup
                          </Link>
                          <Link href={getEditReviewPath(account.key)} style={inlineLinkStyle}>
                            Review
                          </Link>
                          <span style={{ ...mutedTextStyle, fontSize: '13px' }}>
                            Status toggle comes in the real API phase.
                          </span>
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
          <strong>Phase 1 placeholder boundary</strong>
          <p style={mutedTextStyle}>
            This page intentionally stops at operator routing, list visibility, and placeholder
            status display. Real list fetching, filters, status mutation, and persistence are
            later-phase work.
          </p>
        </article>
      </section>
    </ControlPlaneShell>
  );
}
