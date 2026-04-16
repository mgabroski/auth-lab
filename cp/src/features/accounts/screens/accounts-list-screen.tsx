'use client';

/**
 * cp/src/features/accounts/screens/accounts-list-screen.tsx
 *
 * WHY:
 * - Renders the CP accounts list for operator re-entry and edit routing.
 * - Phase 5 adds practical re-entry actions for existing draft/published accounts
 *   and a real backend-owned Active/Disabled status toggle.
 */

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import type { CSSProperties } from 'react';
import { useMemo, useState } from 'react';
import type {
  ControlPlaneAccountDetail,
  ControlPlaneAccountListItem,
  FooterAction,
} from '../contracts';
import { updateCpAccountStatus } from '../cp-accounts-client';
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

const inlineButtonStyle: CSSProperties = {
  appearance: 'none',
  border: '1px solid #cbd5e1',
  backgroundColor: '#ffffff',
  color: '#0f172a',
  borderRadius: '999px',
  padding: '6px 12px',
  fontSize: '12px',
  fontWeight: 700,
  cursor: 'pointer',
};

const disabledButtonStyle: CSSProperties = {
  ...inlineButtonStyle,
  cursor: 'not-allowed',
  opacity: 0.65,
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

function accountListRowFromDetail(account: ControlPlaneAccountDetail): ControlPlaneAccountListItem {
  return {
    id: account.id,
    accountName: account.accountName,
    accountKey: account.accountKey,
    cpStatus: account.cpStatus,
    cpRevision: account.cpRevision,
    step2Progress: account.step2Progress,
  };
}

export function AccountsListScreen({ accounts }: { accounts: ControlPlaneAccountListItem[] }) {
  const router = useRouter();
  const [accountRows, setAccountRows] = useState(accounts);
  const [busyAccountKey, setBusyAccountKey] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ tone: 'success' | 'error'; message: string } | null>(
    null,
  );

  const footerActions: FooterAction[] = [
    {
      label: 'Create Account',
      href: getCreateFlowEntryPath(),
      variant: 'primary',
    },
  ];

  const summary = useMemo(() => {
    const activeCount = accountRows.filter((account) => account.cpStatus === 'Active').length;
    const draftCount = accountRows.filter((account) => account.cpStatus === 'Draft').length;
    const disabledCount = accountRows.filter((account) => account.cpStatus === 'Disabled').length;

    return {
      totalCount: accountRows.length,
      activeCount,
      draftCount,
      disabledCount,
    };
  }, [accountRows]);

  async function handleStatusToggle(account: ControlPlaneAccountListItem) {
    if (account.cpStatus === 'Draft') {
      return;
    }

    const targetStatus = account.cpStatus === 'Active' ? 'Disabled' : 'Active';

    setBusyAccountKey(account.accountKey);
    setFeedback(null);

    try {
      const updated = await updateCpAccountStatus(account.accountKey, { targetStatus });

      setAccountRows((currentRows) =>
        currentRows.map((row) =>
          row.accountKey === account.accountKey ? accountListRowFromDetail(updated) : row,
        ),
      );

      setFeedback({
        tone: 'success',
        message: `${updated.accountName} is now ${updated.cpStatus}.`,
      });
      router.refresh();
    } catch (error) {
      setFeedback({
        tone: 'error',
        message: error instanceof Error ? error.message : 'Status update failed.',
      });
    } finally {
      setBusyAccountKey(null);
    }
  }

  return (
    <ControlPlaneShell
      currentPath="Accounts"
      pageTitle="Accounts"
      pageDescription="Find existing tenant accounts, re-open saved group pages, re-review changes, and toggle Active or Disabled without DB work."
      footerActions={footerActions}
    >
      <section style={sectionGridStyle}>
        <div style={infoGridStyle}>
          <article style={infoCardStyle}>
            <p style={labelStyle}>Total accounts</p>
            <p style={valueStyle}>{summary.totalCount}</p>
          </article>

          <article style={infoCardStyle}>
            <p style={labelStyle}>Draft</p>
            <p style={valueStyle}>{summary.draftCount}</p>
          </article>

          <article style={infoCardStyle}>
            <p style={labelStyle}>Active</p>
            <p style={valueStyle}>{summary.activeCount}</p>
          </article>

          <article style={infoCardStyle}>
            <p style={labelStyle}>Disabled</p>
            <p style={valueStyle}>{summary.disabledCount}</p>
          </article>
        </div>

        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>All accounts</h2>
          {feedback ? (
            <p
              style={{
                ...mutedTextStyle,
                color: feedback.tone === 'success' ? '#166534' : '#991b1b',
                fontWeight: 700,
              }}
            >
              {feedback.message}
            </p>
          ) : null}

          {accountRows.length === 0 ? (
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
                  {accountRows.map((account) => {
                    const isBusy = busyAccountKey === account.accountKey;
                    const toggleLabel = account.cpStatus === 'Active' ? 'Disable' : 'Activate';
                    const reviewLabel = account.cpStatus === 'Draft' ? 'Review' : 'Review & Save';

                    return (
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
                            <Link
                              href={getEditSetupPath(account.accountKey)}
                              style={inlineLinkStyle}
                            >
                              Edit Setup
                            </Link>
                            <Link
                              href={getEditReviewPath(account.accountKey)}
                              style={inlineLinkStyle}
                            >
                              {reviewLabel}
                            </Link>
                            {account.cpStatus === 'Draft' ? (
                              <span style={mutedTextStyle}>Review first to publish.</span>
                            ) : (
                              <button
                                type="button"
                                style={isBusy ? disabledButtonStyle : inlineButtonStyle}
                                disabled={isBusy}
                                onClick={() => {
                                  void handleStatusToggle(account);
                                }}
                              >
                                {isBusy ? 'Saving…' : toggleLabel}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </article>

        <article style={insetPanelStyle}>
          <strong>Phase 5 operator surface</strong>
          <p style={mutedTextStyle}>
            Accounts list, edit/re-entry, re-review, and the Active/Disabled status toggle are now
            real. Draft accounts still move through Review & Publish to leave Draft for the first
            time.
          </p>
        </article>
      </section>
    </ControlPlaneShell>
  );
}
