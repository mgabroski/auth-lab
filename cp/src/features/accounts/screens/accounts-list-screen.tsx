import Link from 'next/link';
import type { CSSProperties } from 'react';
import type { ControlPlaneAccountListItem, FooterAction } from '../contracts';
import { getCreateFlowEntryPath, getEditSetupPath, getEditReviewPath } from '@/shared/cp/links';
import {
  contentPanelStyle,
  infoCardStyle,
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

const tableHeaderCellStyle: CSSProperties = {
  ...tableCellStyle,
  borderTop: 'none',
  fontSize: '12px',
  fontWeight: 700,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  color: '#64748b',
};

type AccountsListScreenProps = {
  accounts: ControlPlaneAccountListItem[];
};

export function AccountsListScreen({ accounts }: AccountsListScreenProps) {
  const footerActions: FooterAction[] = [
    {
      label: 'Create Account',
      href: getCreateFlowEntryPath(),
      variant: 'primary',
    },
  ];

  return (
    <ControlPlaneShell
      currentPath="Accounts"
      pageTitle="Accounts list"
      pageDescription="Minimal Phase 1 list view for QA re-entry, edit routing, and review routing."
      footerActions={footerActions}
    >
      <section style={sectionGridStyle}>
        <article style={infoCardStyle}>
          <p style={labelStyle}>Phase 1 note</p>
          <p style={valueStyle}>This page is intentionally minimal and route-focused.</p>
          <p style={mutedTextStyle}>
            It exists so operators can re-enter an existing account draft or published account while
            Phase 2 APIs and persistence are still out of scope.
          </p>
        </article>

        <article style={contentPanelStyle}>
          <h2 style={sectionTitleStyle}>Existing accounts</h2>
          <div style={{ overflowX: 'auto' }}>
            <table style={tableStyle}>
              <thead>
                <tr>
                  <th style={tableHeaderCellStyle}>Account name</th>
                  <th style={tableHeaderCellStyle}>Account key</th>
                  <th style={tableHeaderCellStyle}>Status</th>
                  <th style={tableHeaderCellStyle}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {accounts.map((account) => (
                  <tr key={account.id}>
                    <td style={tableCellStyle}>{account.name}</td>
                    <td style={tableCellStyle}>{account.key}</td>
                    <td style={tableCellStyle}>{account.cpStatus}</td>
                    <td style={tableCellStyle}>
                      <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                        <Link href={getEditSetupPath(account.key)} style={inlineLinkStyle}>
                          Edit
                        </Link>
                        <Link href={getEditReviewPath(account.key)} style={inlineLinkStyle}>
                          Review
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </article>

        <article style={insetPanelStyle}>
          <strong>Placeholder data boundary</strong>
          <p style={mutedTextStyle}>
            The list entries on this page are backed by typed in-memory placeholders only.
            Persistence, filtering, and real list fetches are Phase 2 work.
          </p>
        </article>
      </section>
    </ControlPlaneShell>
  );
}
