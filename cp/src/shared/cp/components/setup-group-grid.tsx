import Link from 'next/link';
import type { CSSProperties } from 'react';
import type { CpStep2Progress, SetupGroupSlug } from '@/features/accounts/contracts';
import { infoCardStyle, infoGridStyle, labelStyle, valueStyle } from '../styles';

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

const stateBadgeStyle = (configured: boolean): CSSProperties => ({
  display: 'inline-flex',
  width: 'fit-content',
  padding: '6px 10px',
  borderRadius: '999px',
  fontSize: '12px',
  fontWeight: 700,
  color: configured ? '#166534' : '#92400e',
  backgroundColor: configured ? '#dcfce7' : '#fef3c7',
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

const summaryBoxStyle = (configured: boolean): CSSProperties => ({
  padding: '12px 14px',
  borderRadius: '14px',
  border: `1px solid ${configured ? '#bbf7d0' : '#fde68a'}`,
  backgroundColor: configured ? '#f0fdf4' : '#fffbeb',
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
  progress: CpStep2Progress;
  getGroupHref: (groupSlug: SetupGroupSlug) => string;
};

export function SetupGroupGrid({ progress, getGroupHref }: SetupGroupGridProps) {
  return (
    <div style={infoGridStyle}>
      {progress.groups.map((group, index) => {
        const actionLabel = group.configured
          ? `Review ${group.title} group`
          : `Configure ${group.title} group`;

        return (
          <article
            key={group.slug}
            data-testid={`cp-setup-group-card-${group.slug}`}
            style={infoCardStyle}
          >
            <div style={headerRowStyle}>
              <span style={groupNumberStyle}>Group {index + 1}</span>
              <span style={stateBadgeStyle(group.configured)}>
                {group.configured ? 'Configured' : 'Needs save'}
              </span>
            </div>

            <div style={{ display: 'grid', gap: '6px' }}>
              <p style={labelStyle}>Setup group</p>
              <p style={valueStyle}>{group.title}</p>
            </div>

            <div style={metaRowStyle}>
              <span style={metaBadgeStyle('neutral')}>
                {group.isRequired ? 'Required' : 'Optional'}
              </span>
              <span style={metaBadgeStyle('blue')}>Step 2 group</span>
            </div>

            <div style={summaryBoxStyle(group.configured)}>
              <p style={summaryTitleStyle}>
                {group.configured ? 'Current state' : 'Action needed'}
              </p>
              <p style={summaryTextStyle}>
                {group.configured
                  ? 'This group has been explicitly saved and now contributes real CP allowance truth.'
                  : 'Open the group, make the required decisions, and save before continuing.'}
              </p>
            </div>

            <Link href={getGroupHref(group.slug)} aria-label={actionLabel} style={linkStyle}>
              {group.configured ? 'Review group →' : 'Configure group →'}
            </Link>
          </article>
        );
      })}
    </div>
  );
}
