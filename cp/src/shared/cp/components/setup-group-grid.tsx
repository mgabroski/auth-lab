import Link from 'next/link';
import type { CSSProperties } from 'react';
import type { ControlPlaneAccountDraft, SetupGroupSlug } from '@/features/accounts/contracts';
import { SETUP_GROUPS } from '@/features/accounts/setup-groups';
import { infoCardStyle, infoGridStyle, labelStyle, mutedTextStyle, valueStyle } from '../styles';

const headerRowStyle: CSSProperties = {
  display: 'flex',
  alignItems: 'flex-start',
  justifyContent: 'space-between',
  gap: '12px',
};

const groupNumberStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  minWidth: '32px',
  height: '32px',
  padding: '0 10px',
  borderRadius: '999px',
  backgroundColor: '#e2e8f0',
  color: '#0f172a',
  fontSize: '13px',
  fontWeight: 800,
};

const stateBadgeStyle = (reviewed: boolean): CSSProperties => ({
  display: 'inline-flex',
  width: 'fit-content',
  padding: '6px 10px',
  borderRadius: '999px',
  fontSize: '12px',
  fontWeight: 700,
  color: reviewed ? '#166534' : '#92400e',
  backgroundColor: reviewed ? '#dcfce7' : '#fef3c7',
});

const metaRowStyle: CSSProperties = {
  display: 'flex',
  flexWrap: 'wrap',
  gap: '8px',
};

const metaBadgeStyle = (variant: 'neutral' | 'blue'): CSSProperties => ({
  display: 'inline-flex',
  alignItems: 'center',
  padding: '6px 10px',
  borderRadius: '999px',
  fontSize: '12px',
  fontWeight: 700,
  backgroundColor: variant === 'blue' ? '#dbeafe' : '#e2e8f0',
  color: variant === 'blue' ? '#1d4ed8' : '#334155',
});

const summaryBoxStyle = (reviewed: boolean): CSSProperties => ({
  padding: '12px 14px',
  borderRadius: '14px',
  border: `1px solid ${reviewed ? '#bbf7d0' : '#fde68a'}`,
  backgroundColor: reviewed ? '#f0fdf4' : '#fffbeb',
  display: 'grid',
  gap: '4px',
});

const summaryTitleStyle: CSSProperties = {
  margin: 0,
  fontSize: '13px',
  fontWeight: 700,
  color: '#0f172a',
};

const summaryTextStyle: CSSProperties = {
  margin: 0,
  fontSize: '13px',
  lineHeight: 1.6,
  color: '#475569',
};

const linkStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  width: 'fit-content',
  fontSize: '14px',
  fontWeight: 700,
  textDecoration: 'none',
  color: '#0f172a',
};

type SetupGroupGridProps = {
  account: Pick<ControlPlaneAccountDraft, 'setupGroupsReviewed'>;
  getGroupHref: (groupSlug: SetupGroupSlug) => string;
};

export function SetupGroupGrid({ account, getGroupHref }: SetupGroupGridProps) {
  return (
    <div style={infoGridStyle}>
      {SETUP_GROUPS.map((group, index) => {
        const reviewed = account.setupGroupsReviewed.includes(group.slug);

        return (
          <article key={group.slug} style={infoCardStyle}>
            <div style={headerRowStyle}>
              <span style={groupNumberStyle}>Group {index + 1}</span>
              <span style={stateBadgeStyle(reviewed)}>
                {reviewed ? 'Configured in draft' : 'Needs review'}
              </span>
            </div>

            <div style={{ display: 'grid', gap: '6px' }}>
              <p style={labelStyle}>Setup group</p>
              <p style={valueStyle}>{group.title}</p>
              <p style={mutedTextStyle}>{group.description}</p>
            </div>

            <div style={metaRowStyle}>
              <span style={metaBadgeStyle('neutral')}>Step 2 group</span>
              <span style={metaBadgeStyle('blue')}>Phase 1 placeholder boundary</span>
            </div>

            <div style={summaryBoxStyle(reviewed)}>
              <p style={summaryTitleStyle}>
                {reviewed ? 'Current draft state' : 'What happens next'}
              </p>
              <p style={summaryTextStyle}>
                {reviewed
                  ? 'This group is currently marked as reviewed in the placeholder draft state for this account.'
                  : 'Open this group, review the locked Control Plane decisions, and save the draft state before continuing.'}
              </p>
            </div>

            <Link href={getGroupHref(group.slug)} style={linkStyle}>
              Open group →
            </Link>
          </article>
        );
      })}
    </div>
  );
}
